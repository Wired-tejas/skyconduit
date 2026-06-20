import http from 'http';
import https from 'https';
import { URL } from 'url';
import { Transform, TransformCallback } from 'stream';
import { pipeline } from 'stream/promises';
import { ssrfSafeHttpAgent, ssrfSafeHttpsAgent } from './security';
import crypto from 'crypto';

export interface TransferMetrics {
  bytesTransferred: number;
  sha256: string;
}

export interface TransferOptions {
  method?: 'POST' | 'PUT';
  headers?: Record<string, string>;
}

/**
 * Custom pass-through stream that performs on-the-fly telemetry.
 * It tracks transfer progress and incrementally builds a SHA-256 hash
 * with an O(1) memory footprint.
 */
export class StreamMetricsTransformer extends Transform {
  private bytesTransferred = 0;
  private sha256Hasher = crypto.createHash('sha256');

  constructor() {
    super();
  }

  override _transform(chunk: any, encoding: BufferEncoding, callback: TransformCallback): void {
    try {
      const len = chunk.length;
      this.bytesTransferred += len;
      this.sha256Hasher.update(chunk);

      // Emit periodic progress events (e.g., for external tracking hooks)
      this.emit('progress', this.bytesTransferred);

      // Pass the unmodified chunk down the pipeline (Zero-Copy propagation)
      this.push(chunk);
      callback();
    } catch (err: any) {
      callback(err);
    }
  }

  /**
   * Safe intermediate metrics retrieval by cloning hash state.
   */
  getIntermediateMetrics(): TransferMetrics {
    return {
      bytesTransferred: this.bytesTransferred,
      sha256: this.sha256Hasher.copy().digest('hex'),
    };
  }

  /**
   * Finalizes the hash and returns complete metrics.
   */
  getFinalMetrics(): TransferMetrics {
    return {
      bytesTransferred: this.bytesTransferred,
      sha256: this.sha256Hasher.digest('hex'),
    };
  }
}

/**
 * Resolves the appropriate node agent based on URL protocol.
 */
function getAgentForUrl(urlObj: URL): typeof http.Agent {
  if (urlObj.protocol === 'https:') {
    return ssrfSafeHttpsAgent;
  } else if (urlObj.protocol === 'http:') {
    return ssrfSafeHttpAgent;
  }
  throw new Error(`Unsupported protocol: ${urlObj.protocol}`);
}

/**
 * Establishes an outbound request client for the file stream source.
 */
function fetchSourceStream(urlStr: string): Promise<{ stream: http.IncomingMessage; contentType: string; contentLength?: number }> {
  return new Promise((resolve, reject) => {
    try {
      const urlObj = new URL(urlStr);
      const client = urlObj.protocol === 'https:' ? https : http;
      const agent = getAgentForUrl(urlObj);

      const req = client.get(
        urlStr,
        { agent, timeout: 15000 },
        (res) => {
          if (res.statusCode && (res.statusCode < 200 || res.statusCode >= 300)) {
            res.resume(); // Free memory
            return reject(new Error(`Failed to fetch source: Status Code ${res.statusCode}`));
          }
          const contentType = res.headers['content-type'] || 'application/octet-stream';
          const contentLengthStr = res.headers['content-length'];
          const contentLength = contentLengthStr ? parseInt(contentLengthStr, 10) : undefined;

          resolve({ stream: res, contentType, contentLength });
        }
      );

      req.on('error', (err) => reject(err));
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Source request timed out'));
      });
    } catch (err) {
      reject(err);
    }
  });
}

/**
 * Executes a zero-buffer, memory-bounded remote-to-remote file transfer.
 * Data flows directly from the source response stream, through the telemetry transformer,
 * and into the target destination upload request stream.
 */
export async function executeTransferPipeline(
  sourceUrl: string,
  destinationUrl: string,
  options: TransferOptions = {}
): Promise<TransferMetrics> {
  const destUrlObj = new URL(destinationUrl);
  const destClient = destUrlObj.protocol === 'https:' ? https : http;
  const destAgent = getAgentForUrl(destUrlObj);

  // 1. Establish connection to the source stream
  const { stream: sourceStream, contentType, contentLength } = await fetchSourceStream(sourceUrl);

  // 2. Instantiate progress telemetry
  const metricsTransformer = new StreamMetricsTransformer();

  return new Promise(async (resolve, reject) => {
    let pipelineCompleted = false;

    // 3. Prepare target request
    const uploadMethod = options.method || 'POST';
    const uploadHeaders: Record<string, string> = {
      'Content-Type': contentType,
      ...options.headers,
    };

    if (contentLength !== undefined) {
      uploadHeaders['Content-Length'] = contentLength.toString();
    } else {
      // Use Chunked Transfer Encoding if source size is unknown
      uploadHeaders['Transfer-Encoding'] = 'chunked';
    }

    const uploadReq = destClient.request(
      destinationUrl,
      {
        method: uploadMethod,
        headers: uploadHeaders,
        agent: destAgent,
        timeout: 30000,
      },
      (res) => {
        // Handle upload server response
        res.on('data', () => {}); // Consume response data to prevent stream leaks
        res.on('end', () => {
          if (res.statusCode && (res.statusCode < 200 || res.statusCode >= 300)) {
            if (!pipelineCompleted) {
              reject(new Error(`Destination upload failed with status: ${res.statusCode}`));
            }
          } else {
            pipelineCompleted = true;
            resolve(metricsTransformer.getFinalMetrics());
          }
        });
      }
    );

    uploadReq.on('error', (err) => {
      if (!pipelineCompleted) {
        sourceStream.destroy();
        reject(err);
      }
    });

    uploadReq.on('timeout', () => {
      uploadReq.destroy();
      sourceStream.destroy();
      reject(new Error('Destination request timed out'));
    });

    // 4. Run stream pipeline incorporating automatic backpressure and error cleanup
    try {
      await pipeline(
        sourceStream,
        metricsTransformer,
        uploadReq
      );
    } catch (pipelineErr) {
      if (!pipelineCompleted) {
        uploadReq.destroy();
        sourceStream.destroy();
        reject(pipelineErr);
      }
    }
  });
}