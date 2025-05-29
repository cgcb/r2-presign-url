/**
 * @description Cloudflare Worker to generate presigned R2 PUT URLs with JWT authentication and typed uploads.
 *              Key features include: per-file configurable Cache-Control (defaulting to aggressive public caching)
 *              and If-None-Match headers to prevent object overwrites (both included in SigV4 signature);
 *              robust JWT validation using 'jose'; presigned URL generation via 'aws4fetch';
 *              dynamic R2 endpoint creation using CLOUDFLARE_ACCOUNT_ID; cached S3 client;
 *              configurable operational parameters (max files, expiry, timeouts, payload size) via environment
 *              variables with fallbacks; concurrency limiting for presign operations; Hono for routing and
 *              body-limit middleware; and RFC 7807 compliant error responses.
 * 
 * @author      Chris Brewer <https://github.com/cgcb>
 * @version     1.0.0
 * @modified    2025-05-28
 *
 * @exampleRequestPayload
 * // POST /generate-presigned-urls
 * // Body:
 * {
 *   "files": [
 *     {
 *       "filename": "photo.jpg",
 *       "type": "item_image",
 *       "cache_control": {
 *         "max_age": 86400, // Override: 1 day
 *         "immutable": true
 *       }
 *     },
 *     {
 *       "filename": "another-image.png",
 *       "type": "item_image",
 *       "cache_control": {
 *         "immutable": false // Override: make revalidate, max_age defaults to 1 year (31536000s)
 *       }
 *     },
 *     {
 *       "filename": "avatar.webp",
 *       "type": "avatar"
 *       // No cache_control: defaults to 'public, max-age=31536000, immutable'
 *     }
 *   ],
 *   "presign_options": { // Optional
 *     "expires_in_seconds": 600 // Presigned URL itself expires in 10 minutes
 *   }
 * }
 *
 * @dependencies
 *   Hono: ^4.7.10
 *   jose: ^6.0.11
 *   aws4fetch: ^1.0.17
 *   hono/body-limit
 *   hono/http-exception
 *
 * @runtime Target: Modern Cloudflare Workers Runtime
 */

import { Hono } from 'hono';
import { jwtVerify } from 'jose/jwt/verify';
import { JWTExpired, JWKInvalid, JWTClaimValidationFailed } from 'jose/errors';
import { bodyLimit } from 'hono/body-limit';
import { HTTPException } from 'hono/http-exception';
import { AwsClient } from 'aws4fetch';

const textEncoder = new TextEncoder();

// --- Application Version ---
const WORKER_VERSION = '1.0.56';

// --- Static Initializations ---
const TRAILING_SLASH_REGEX = Object.freeze(/\/+$/);

let jwtSecretKeyCache = null;

// --- RFC 7807 Problem Types ---
const PROBLEM_TYPES_BASE_URL = 'https://your-domain.com/errors/';
const PROBLEM_TYPES = Object.freeze({
	// 400 Bad Request & 422 Unprocessable Entity
	VALIDATION_FAILED: `${PROBLEM_TYPES_BASE_URL}validation-failed`,
	MISSING_PARAMETER: `${PROBLEM_TYPES_BASE_URL}missing-parameter`,
	INVALID_PARAMETER_VALUE: `${PROBLEM_TYPES_BASE_URL}invalid-parameter-value`,
	MALFORMED_REQUEST_BODY: `${PROBLEM_TYPES_BASE_URL}malformed-request-body`,
	INVALID_FILE_ENTRY: `${PROBLEM_TYPES_BASE_URL}invalid-file-entry`, // For individual file errors in a 207

	// 401 Unauthorized
	AUTHENTICATION_REQUIRED: `${PROBLEM_TYPES_BASE_URL}authentication-required`,
	TOKEN_EXPIRED: `${PROBLEM_TYPES_BASE_URL}token-expired`,
	TOKEN_INVALID: `${PROBLEM_TYPES_BASE_URL}token-invalid`, // General invalid structure, signature
	TOKEN_CLAIM_INVALID: `${PROBLEM_TYPES_BASE_URL}token-claim-invalid`,

	// 403 Forbidden (If needed in future, e.g., insufficient scope)
	// AUTHORIZATION_FAILED: `${PROBLEM_TYPES_BASE_URL}authorization-failed`,

	// 413 Payload Too Large
	PAYLOAD_TOO_LARGE: `${PROBLEM_TYPES_BASE_URL}payload-too-large`,

	// 500 Internal Server Error
	INTERNAL_SERVER_ERROR: `${PROBLEM_TYPES_BASE_URL}internal-server-error`,
	S3_CLIENT_INIT_FAILURE: `${PROBLEM_TYPES_BASE_URL}s3-client-initialization-failed`,
	PRESIGN_OPERATION_FAILED: `${PROBLEM_TYPES_BASE_URL}presign-operation-failed`,
	PRESIGN_TIMEOUT: `${PROBLEM_TYPES_BASE_URL}presign-timeout`, // For individual file errors in a 207 or if all timeout

	// 503 Service Unavailable (If needed, e.g. R2 down)
	// SERVICE_UNAVAILABLE: `${PROBLEM_TYPES_BASE_URL}service-unavailable`,
});


// --- Configurable Constants with Fallbacks ---
// These functions read from c.env if available, otherwise use hardcoded defaults.
// This allows runtime configuration without code changes.

// Default values (hardcoded fallbacks)
const FALLBACK_DEFAULT_MAX_FILES = 200;
const FALLBACK_DEFAULT_PRESIGNED_URL_EXPIRY_SECONDS = 300; // 5 minutes
const FALLBACK_MIN_PRESIGNED_URL_EXPIRY_SECONDS = 60;     // 1 minute
const FALLBACK_MAX_PRESIGNED_URL_EXPIRY_SECONDS = 3600;   // 1 hour
const FALLBACK_MAX_PAYLOAD_SIZE_BYTES = 512 * 1024;       // 0.5 MB
const FALLBACK_PRESIGN_OPERATION_TIMEOUT_MS = 5000;       // 5 seconds
const FALLBACK_PRESIGN_REQUEST_CONCURRENCY_LIMIT = 10;

function getConfigOrDefault(envValue, defaultValue, isInt = true) {
	if (envValue === undefined || envValue === null || envValue === '') {
		return defaultValue;
	}
	if (isInt) {
		const parsed = parseInt(envValue, 10);
		return !Number.isNaN(parsed) && Number.isFinite(parsed) ? parsed : defaultValue;
	}
	return envValue; // For non-integer values if any in future
}

// Accessor functions for config values used within request handlers (taking `c` for `c.env`)
const getMaxFiles = (c_env) => getConfigOrDefault(c_env.MAX_FILES, FALLBACK_DEFAULT_MAX_FILES);
const getDefaultPresignedUrlExpirySeconds = (c_env) => getConfigOrDefault(c_env.PRESIGNED_URL_EXPIRATION_SECONDS, FALLBACK_DEFAULT_PRESIGNED_URL_EXPIRY_SECONDS);
const getMinPresignedUrlExpirySeconds = (c_env) => getConfigOrDefault(c_env.MIN_PRESIGNED_URL_EXPIRATION_SECONDS, FALLBACK_MIN_PRESIGNED_URL_EXPIRY_SECONDS);
const getMaxPresignedUrlExpirySeconds = (c_env) => getConfigOrDefault(c_env.MAX_PRESIGNED_URL_EXPIRATION_SECONDS, FALLBACK_MAX_PRESIGNED_URL_EXPIRY_SECONDS);
const getMaxPayloadSizeBytes = (c_env) => getConfigOrDefault(c_env.MAX_PAYLOAD_SIZE_BYTES, FALLBACK_MAX_PAYLOAD_SIZE_BYTES);
const getPresignOperationTimeoutMs = (c_env) => getConfigOrDefault(c_env.PRESIGN_OPERATION_TIMEOUT_MS, FALLBACK_PRESIGN_OPERATION_TIMEOUT_MS);
const getPresignRequestConcurrencyLimit = (c_env) => getConfigOrDefault(c_env.PRESIGN_REQUEST_CONCURRENCY_LIMIT, FALLBACK_PRESIGN_REQUEST_CONCURRENCY_LIMIT);


// --- Helper: Promise with Timeout ---
/**
 * Race a promise against a timeout, rejecting with custom error.
 *
 * @param {Promise<any>} promise The promise to race against the timeout.
 * @param {number} ms The timeout duration in milliseconds.
 * @param {() => { success:false, detail: string, reason_code: string, timeout:true, filename?: string }} timeoutErrorFactory A function that returns the error to be thrown on timeout.
 * @returns {Promise<any>} Resolves with the promise's resolution or rejects with the timeout error.
 */
function promiseWithTimeout(promise, ms, timeoutErrorFactory) {
	let timeoutId;
	const timeoutPromise = new Promise((_, reject) => {
		timeoutId = setTimeout(() => {
			reject(timeoutErrorFactory());
		}, ms);
	});

	return Promise.race([promise, timeoutPromise])
		.finally(() => {
			clearTimeout(timeoutId);
		});
}

// --- Helper: Concurrency Limiter ---
/**
 * Run an array of async thunks with at most `limit` concurrent executions.
 *
 * @param {Array<() => Promise<any>>} tasks - An array of functions that return Promises.
 * @param {number} limit - The maximum number of tasks to run concurrently.
 * @returns {Promise<Array<PromiseSettledResult<any>>>} - A Promise that resolves with an array of PromiseSettledResult objects.
 */
async function limitedConcurrency(tasks, limit) {
	const results = [];
	const executing = [];
	for (const taskThunk of tasks) {
		const p = Promise.resolve().then(() => taskThunk());
		results.push(p);
		const e = p.finally(() => executing.splice(executing.indexOf(e), 1));
		executing.push(e);
		if (executing.length >= limit) {
			await Promise.race(executing);
		}
	}
	return Promise.allSettled(results);
}

// --- Constants ---
const ALLOWED_EXTENSIONS = Object.freeze({
	jpg: 'image/jpeg',
	jpeg: 'image/jpeg',
	png: 'image/png',
	webp: 'image/webp',
	mp3: 'audio/mpeg',
	m4a: 'audio/mp4'
});

const ALLOWED_UPLOAD_TYPES = Object.freeze({
	item_image: 'items',
	item_recording: 'recordings',
	avatar: 'avatars'
});

const REASON_CODES = Object.freeze({
	STRUCTURAL: Object.freeze({
		MALFORMED_ENTRY: 'MALFORMED_ENTRY',
		PAYLOAD_TOO_LARGE: 'PAYLOAD_TOO_LARGE',
		MISSING_FILES_ARRAY: 'MISSING_FILES_ARRAY',
		TOO_MANY_FILES: 'TOO_MANY_FILES',
	}),
	VALIDATION: Object.freeze({
		EMPTY_FILENAME: 'EMPTY_FILENAME',
		INVALID_FILENAME: 'INVALID_FILENAME',
		MISSING_EXTENSION: 'MISSING_EXTENSION',
		UNSUPPORTED_EXTENSION: 'UNSUPPORTED_EXTENSION',
		UNSUPPORTED_TYPE: 'UNSUPPORTED_TYPE',
		INVALID_PARAMETER: 'INVALID_PARAMETER',
		INVALID_EXPIRY_FORMAT: 'INVALID_EXPIRY_FORMAT',
		EXPIRY_TOO_SHORT: 'EXPIRY_TOO_SHORT',
		EXPIRY_TOO_LONG: 'EXPIRY_TOO_LONG',
		INVALID_CACHE_CONTROL_MAX_AGE: 'INVALID_CACHE_CONTROL_MAX_AGE',
		INVALID_CACHE_CONTROL_IMMUTABLE: 'INVALID_CACHE_CONTROL_IMMUTABLE',
	}),
	RUNTIME: Object.freeze({
		PRESIGN_TIMEOUT: 'PRESIGN_TIMEOUT',
		PRESIGN_API_ERROR: 'PRESIGN_API_ERROR',
		UNEXPECTED_PROCESSING_ERROR: 'UNEXPECTED_PROCESSING_ERROR',
		INTERNAL_SERVER_ERROR: 'INTERNAL_SERVER_ERROR',
		S3_CLIENT_INIT_FAILURE: 'S3_CLIENT_INIT_FAILURE',
		TOKEN_VALIDATION_FAILED: 'TOKEN_VALIDATION_FAILED',
		TOKEN_EXPIRED: 'TOKEN_EXPIRED',
		TOKEN_CLAIM_INVALID: 'TOKEN_CLAIM_INVALID',
	})
});

const INVALID_FILENAME_CHARS_REGEX = Object.freeze(/[\\/]/);


// --- Helper: S3 Client Initialization ---
/**
 * Initializes and/or returns a cached AwsClient for S3 operations and the R2 base URL.
 * Manages a module-scoped cache and initialization error state.
 * Checks for all required S3/R2 related environment variables.
 * Logs activity if DEBUG_LOGGING is enabled in the environment.
 *
 * @param {import('hono').Context} c - The Hono context, used to access environment variables (c.env).
 * @returns {{ client: AwsClient | null, r2BaseUrl: string | null, error: string | null, reason_code: string | null }} An object containing the S3 client instance, the R2 base URL (or nulls if initialization failed), any initialization error message, and a reason code.
 */
const getS3ClientInternal = (() => {
	let client = null;
	let r2BaseUrl = null;
	let initError = null;
	let initReasonCode = null;

	return (c) => {
		const DEBUG_MODE = ['true', '1', 'yes'].includes(String(c.env.DEBUG_LOGGING).toLowerCase());

		if (initError) {
			if (DEBUG_MODE) console.log("S3 client previously failed initialization. Returning error.");
			return { client: null, r2BaseUrl: null, error: initError, reason_code: initReasonCode };
		}
		if (client && r2BaseUrl) {
			if (DEBUG_MODE) console.log("Using cached AwsClient and R2 base URL.");
			return { client, r2BaseUrl, error: null, reason_code: null };
		}

		const { R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, CLOUDFLARE_ACCOUNT_ID, R2_PUBLIC_URL_PREFIX, R2_BUCKET_NAME } = c.env;

		// Clear any previous partial initialization state
		client = null;
		r2BaseUrl = null;
		initError = null;
		initReasonCode = null;

		if (!R2_ACCESS_KEY_ID) {
			initError = "CRITICAL: R2_ACCESS_KEY_ID is not configured.";
			initReasonCode = REASON_CODES.RUNTIME.S3_CLIENT_INIT_FAILURE;
		} else if (!R2_SECRET_ACCESS_KEY) {
			initError = "CRITICAL: R2_SECRET_ACCESS_KEY is not configured.";
			initReasonCode = REASON_CODES.RUNTIME.S3_CLIENT_INIT_FAILURE;
		} else if (!CLOUDFLARE_ACCOUNT_ID) {
			initError = "CRITICAL: CLOUDFLARE_ACCOUNT_ID is not configured (needed for S3 endpoint).";
			initReasonCode = REASON_CODES.RUNTIME.S3_CLIENT_INIT_FAILURE;
		} else if (!R2_PUBLIC_URL_PREFIX) {
			initError = "CRITICAL: R2_PUBLIC_URL_PREFIX is not configured.";
			initReasonCode = REASON_CODES.RUNTIME.S3_CLIENT_INIT_FAILURE;
		} else if (!R2_BUCKET_NAME) {
			initError = "CRITICAL: R2_BUCKET_NAME is not configured.";
			initReasonCode = REASON_CODES.RUNTIME.S3_CLIENT_INIT_FAILURE;
		}

		if (initError) {
			if (DEBUG_MODE) console.error(`S3 Client Init Failed: ${initError}`);
			return { client: null, r2BaseUrl: null, error: initError, reason_code: initReasonCode };
		}

		try {
			client = new AwsClient({
				accessKeyId: R2_ACCESS_KEY_ID,
				secretAccessKey: R2_SECRET_ACCESS_KEY,
				service: 's3',
				region: 'auto', // R2 is region-less for this purpose, 'auto' is typical.
				// Host is not a direct AwsClient constructor option
			});
			// The base URL for R2 path-style requests.
			r2BaseUrl = `https://${CLOUDFLARE_ACCOUNT_ID}.r2.cloudflarestorage.com`;

			if (DEBUG_MODE) console.log("AwsClient initialized successfully. R2 Base URL:", r2BaseUrl);
			return { client, r2BaseUrl, error: null, reason_code: null };
		} catch (err) {
			initError = `CRITICAL: Failed to initialize AwsClient: ${err.message}`;
			initReasonCode = REASON_CODES.RUNTIME.S3_CLIENT_INIT_FAILURE;
			if (DEBUG_MODE) console.error(initError, err);
			return { client: null, r2BaseUrl: null, error: initError, reason_code: initReasonCode };
		}
	};
})();


// --- Helper: Validate and get file details ---
/**
 * Validates file details and extracts metadata.
 * Also processes optional cache_control settings.
 *
 * @param {string} originalFilename - The filename provided by the client.
 * @param {string} rawUploadType - The upload type string provided by the client.
 * @param {object} [cacheControlOptions] - Optional cache control options from the client { max_age?: number, immutable?: boolean }.
 * @returns {{
 *   success: boolean,
 *   original_filename?: string,
 *   upload_type?: string,
 *   upload_folder?: string,
 *   extension?: string,
 *   content_type?: string,
 *   cache_control_header?: string,
 *   detail?: string,
 *   reason_code?: string
 * }} Validation result.
 */
function validateAndGetFileDetails(originalFilename, rawUploadType, cacheControlOptions) {
	if (typeof originalFilename !== 'string' || originalFilename.trim() === '') {
		return { success: false, detail: 'Filename must be a non-empty string.', reason_code: REASON_CODES.VALIDATION.EMPTY_FILENAME };
	}
	if (originalFilename.length > 255) { // Common filesystem limit, good practice
		return { success: false, detail: 'Filename is too long (max 255 chars).', reason_code: REASON_CODES.VALIDATION.INVALID_FILENAME };
	}
	if (INVALID_FILENAME_CHARS_REGEX.test(originalFilename)) {
		return { success: false, detail: 'Filename contains invalid characters (e.g., slashes).', reason_code: REASON_CODES.VALIDATION.INVALID_FILENAME };
	}

	const parts = originalFilename.toLowerCase().split('.');
	if (parts.length < 2) {
		return { success: false, detail: 'Filename must have an extension.', reason_code: REASON_CODES.VALIDATION.MISSING_EXTENSION };
	}
	const extension = parts.pop();
	const contentType = ALLOWED_EXTENSIONS[extension];
	if (!contentType) {
		return { success: false, detail: `Unsupported file extension: .${extension}`, reason_code: REASON_CODES.VALIDATION.UNSUPPORTED_EXTENSION };
	}

	if (typeof rawUploadType !== 'string' || !ALLOWED_UPLOAD_TYPES[rawUploadType]) {
		return { success: false, detail: `Invalid or missing upload type: ${rawUploadType}`, reason_code: REASON_CODES.VALIDATION.UNSUPPORTED_TYPE };
	}
	const uploadFolder = ALLOWED_UPLOAD_TYPES[rawUploadType];

	// Process Cache-Control
	let maxAge = 31536000; // Default: 1 year
	let isImmutable = true;   // Default: immutable

	if (cacheControlOptions) {
		if (cacheControlOptions.max_age !== undefined) {
			if (typeof cacheControlOptions.max_age === 'number' && cacheControlOptions.max_age >= 0 && Number.isInteger(cacheControlOptions.max_age)) {
				maxAge = cacheControlOptions.max_age;
			} else {
				return { success: false, detail: 'Invalid cache_control.max_age: must be a non-negative integer.', reason_code: REASON_CODES.VALIDATION.INVALID_CACHE_CONTROL_MAX_AGE };
			}
		}
		if (cacheControlOptions.immutable !== undefined) {
			if (typeof cacheControlOptions.immutable === 'boolean') {
				isImmutable = cacheControlOptions.immutable;
			} else {
				return { success: false, detail: 'Invalid cache_control.immutable: must be a boolean.', reason_code: REASON_CODES.VALIDATION.INVALID_CACHE_CONTROL_IMMUTABLE };
			}
		}
	}

	let cacheControlHeaderValue = `public, max-age=${maxAge}`;
	if (isImmutable) {
		cacheControlHeaderValue += ', immutable';
	}

	return {
		success: true,
		original_filename: originalFilename, // Preserve original case for display/metadata if needed
		upload_type: rawUploadType,
		upload_folder: uploadFolder,
		extension: extension,
		content_type: contentType,
		cache_control_header: cacheControlHeaderValue,
	};
}

const app = new Hono();

// Global error handler - RFC 7807 Compliant
app.onError((err, c) => {
	const DEBUG_MODE = ['true', '1', 'yes'].includes(String(c.env.DEBUG_LOGGING).toLowerCase());

	// DIAGNOSTIC LOGGING BLOCK - START
	if (DEBUG_MODE) {
		console.error("Global error handler caught raw error object details:");
		console.error(`Error message: ${err.message}`);
		console.error(`Error name: ${err.name}`);
		
		if (err instanceof HTTPException) { // Only log status if it's an HTTPException, otherwise it might not exist
			console.error(`Error status (from err.status): ${err.status}`);
		}
		
		// Log all enumerable own properties
		console.error("Enumerable own properties of err object:");
		for (const key in err) {
			if (Object.prototype.hasOwnProperty.call(err, key)) {
				try {
					// Attempt to stringify, but be cautious with complex objects or circular refs in errors
					let valueToLog = err[key];
					if (typeof valueToLog === 'function') {
						valueToLog = '[Function]';
					} else if (typeof valueToLog === 'object' && valueToLog !== null) {
						try {
							valueToLog = JSON.stringify(valueToLog);
						} catch (stringifyError) {
							valueToLog = '[Unserializable Object]';
						}
					}
					console.error(`  err.${key}: ${valueToLog}`);
				} catch (e) {
					console.error(`  err.${key}: (could not access or stringify property)`);
				}
			}
		}
		
		// Specifically try to log expected custom properties if it's an HTTPException
		if (err instanceof HTTPException) {
			console.error("Specific Hono HTTPException property checks:");
			console.error(`  Attempt to access err.problemType: ${err.problemType}`);
			console.error(`  Attempt to access err.problemTitle: ${err.problemTitle}`);
			console.error(`  Attempt to access err.reasonCode: ${err.reasonCode}`);
			try {
				console.error(`  Attempt to access err.errors: ${JSON.stringify(err.errors)}`);
			} catch (e) {
				console.error(`  Attempt to access err.errors: (could not stringify)`);
			}
		}

		if (err.cause) { 
			console.error("Error cause property details:");
			try {
				console.error(JSON.stringify(err.cause, null, 2));
			} catch(e) {
				console.error("Could not stringify err.cause");
			}
		}
		console.error("--- End of diagnostic raw error logging ---");
	}
	// DIAGNOSTIC LOGGING BLOCK - END

	let problemDetails = {
		status: 500, 
		instance: new URL(c.req.url).pathname, 
		worker_version: WORKER_VERSION,
		type: PROBLEM_TYPES.INTERNAL_SERVER_ERROR, 
		title: 'Internal Server Error',          
		detail: 'An unexpected error occurred.', 
	};

	if (err instanceof HTTPException) {
		problemDetails.status = err.status;
		problemDetails.detail = err.message || problemDetails.detail;

		problemDetails.type = err.problemType || problemDetails.type; 
		problemDetails.title = err.problemTitle || problemDetails.title;
		
		if (err.reasonCode) problemDetails.reason_code = err.reasonCode;
		if (err.errors) problemDetails.errors = err.errors;

	} else if (err instanceof SyntaxError && err.message.includes('JSON')) {
		problemDetails.status = 400;
		problemDetails.type = PROBLEM_TYPES.MALFORMED_REQUEST_BODY;
		problemDetails.title = 'Malformed JSON';
		problemDetails.detail = `Invalid JSON payload: ${err.message}`;
		problemDetails.reason_code = REASON_CODES.STRUCTURAL.MALFORMED_ENTRY; 
	} else if (err.name === 'BodyLimitError') { 
		problemDetails.status = 413;
		problemDetails.type = PROBLEM_TYPES.PAYLOAD_TOO_LARGE;
		problemDetails.title = 'Payload Too Large';
		problemDetails.detail = err.message || `Request body exceeds the maximum allowed size of ${getMaxPayloadSizeBytes(c.env)} bytes.`;
		problemDetails.reason_code = REASON_CODES.STRUCTURAL.PAYLOAD_TOO_LARGE;
	} else {
		problemDetails.detail = err.message || problemDetails.detail; 
	}
	
	problemDetails.type = problemDetails.type || PROBLEM_TYPES.INTERNAL_SERVER_ERROR;
	problemDetails.title = problemDetails.title || 'Error';
	problemDetails.detail = problemDetails.detail || 'An error occurred.';

	if (DEBUG_MODE) {
		console.error("Responding with problem details:", JSON.stringify(problemDetails, null, 2));
	}

	return c.json(problemDetails, problemDetails.status);
});


// --- Health Check Endpoint ---
app.get('/health', (c) => {
	const deployEnv = c.env.DEPLOY_ENV || 'unknown';
	return c.json({
		status: 'OK',
		version: WORKER_VERSION,
		environment: deployEnv,
		timestamp: new Date().toISOString()
	});
});


// --- Middleware ---

// CORS Middleware
app.use('*', async (c, next) => {
	if (c.req.method === 'OPTIONS') {
		const headers = {
			'Access-Control-Allow-Origin': '*',
				'Access-Control-Allow-Methods': 'POST, OPTIONS',
				'Access-Control-Allow-Headers': 'Content-Type, Authorization',
				'Access-Control-Max-Age': '86400',
			'Vary': 'Origin'
		};
		return new Response(null, { headers });
	}
	await next();
	c.res.headers.set('Access-Control-Allow-Origin', '*');
	c.res.headers.append('Vary', 'Origin');
});

// Body Size Limit Middleware for the presign URL endpoint
app.use('/generate-presigned-urls', async (c, next) => {
	// Dynamically configure bodyLimit middleware
	const currentMaxPayloadSize = getMaxPayloadSizeBytes(c.env);
	const bodyLimitMiddleware = bodyLimit({
		maxSize: currentMaxPayloadSize,
		onError: (ctx) => { // Use a different context variable name like ctx to avoid conflict with outer c
			throw new HTTPException(413, {
				message: `Request body size exceeds the allowed limit of ${currentMaxPayloadSize} bytes.`,
				// problemType, problemTitle will be set by global handler for 413
			});
		}
	});
	// Apply the dynamically configured middleware
	return bodyLimitMiddleware(c, next);
});

// JWT Authentication and Claim Validation Middleware
app.use('/generate-presigned-urls', async (c, next) => {
	const authHeader = c.req.header('Authorization');
	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		throw new HTTPException(401, {
			message: 'Authorization header is missing or not Bearer type.',
			problemType: PROBLEM_TYPES.AUTHENTICATION_REQUIRED,
			problemTitle: 'Authentication Required',
			reasonCode: REASON_CODES.RUNTIME.TOKEN_VALIDATION_FAILED,
		});
	}

	const token = authHeader.substring(7);
	const jwtSecret = c.env.JWT_SECRET;
	if (!jwtSecret) {
		console.error('CRITICAL: JWT_SECRET is not set in environment.');
		throw new HTTPException(500, {
			message: 'JWT secret not configured on server.',
			problemType: PROBLEM_TYPES.INTERNAL_SERVER_ERROR,
			problemTitle: 'Configuration Error',
			reasonCode: REASON_CODES.RUNTIME.INTERNAL_SERVER_ERROR,
		});
	}

	if (!jwtSecretKeyCache) {
		jwtSecretKeyCache = textEncoder.encode(jwtSecret);
	}

	try {
		const { payload } = await jwtVerify(token, jwtSecretKeyCache, {
			issuer: c.env.EXPECTED_ISSUER,
			audience: c.env.EXPECTED_AUDIENCE,
		});
		c.set('jwtPayload', payload);
	} catch (err) {
		console.warn('JWT Verification Error:', err.name, err.message);
		let problemType = PROBLEM_TYPES.TOKEN_INVALID;
		let detailMsg = 'Token is invalid or cannot be processed.';
		let reasonCode = REASON_CODES.RUNTIME.TOKEN_VALIDATION_FAILED;
		let claim;

		if (err instanceof JWTExpired) {
			problemType = PROBLEM_TYPES.TOKEN_EXPIRED;
			detailMsg = `Token has expired. Expired at: ${new Date(err.payload.exp * 1000).toISOString()}`;
			reasonCode = REASON_CODES.RUNTIME.TOKEN_EXPIRED;
		} else if (err instanceof JWKInvalid) {
			detailMsg = 'JWT key processing failed.';
		} else if (err instanceof JWTClaimValidationFailed) {
			problemType = PROBLEM_TYPES.TOKEN_CLAIM_INVALID;
			detailMsg = `Token claim validation failed: "${err.claim}" claim mismatch. Expected "${err.expected}", got "${err.actual}".`;
			reasonCode = REASON_CODES.RUNTIME.TOKEN_CLAIM_INVALID;
			claim = err.claim;
		}

		const httpException = new HTTPException(401, {
			message: detailMsg,
			problemType: problemType,
			problemTitle: 'Unauthorized',
			reasonCode: reasonCode,
		});
		if (claim) httpException.claim = claim;
		throw httpException;
	}
	await next();
});


// --- Main Handler for Presigned URL Generation ---

/**
 * Determines the effective expiration time in seconds for presigned URLs.
 * It considers an environment variable default (`PRESIGNED_URL_EXPIRATION_SECONDS`),
 * an optional request-specific value (`presign_options.expires_in_seconds`),
 * and enforces server-side minimum (from `c.env.MIN_PRESIGNED_URL_EXPIRATION_SECONDS`)
 * and maximum (from `c.env.MAX_PRESIGNED_URL_EXPIRATION_SECONDS`) bounds.
 *
 * @param {import('hono').Context} c - The Hono context for accessing environment variables.
 * @param {object} [requestPresignOptions] - Optional request-specific presign options.
 * @param {number} [requestPresignOptions.expires_in_seconds] - Requested expiry in seconds.
 * @returns {{ expiresIn: number, error?: string, reason_code?: string }}
 *           An object containing the calculated `expiresIn`. If validation fails
 *           or adjustments are made, `error` and `reason_code` fields will be populated.
 */
function getPresignedUrlExpirySeconds(c, requestPresignOptions) {
	// PRESIGNED_URL_EXPIRATION_SECONDS is for client-requested default,
	// DEFAULT_PRESIGNED_URL_EXPIRY_SECONDS is the ultimate fallback for that client default itself.
	const clientDefaultExpiry = parseInt(c.env.PRESIGNED_URL_EXPIRATION_SECONDS, 10) || getDefaultPresignedUrlExpirySeconds(c.env);
	const currentMinPresignedUrlExpirySeconds = getMinPresignedUrlExpirySeconds(c.env);
	const currentMaxPresignedUrlExpirySeconds = getMaxPresignedUrlExpirySeconds(c.env);

	let expiresIn = requestPresignOptions?.expires_in_seconds;
	let error = null;
	let reasonCode = null;

	if (expiresIn !== undefined) {
		if (typeof expiresIn !== 'number' || !Number.isInteger(expiresIn) || expiresIn <= 0) {
			expiresIn = clientDefaultExpiry; // Use the resolved client default
			error = `Invalid 'expires_in_seconds': Must be a positive integer. Using default ${expiresIn}s.`;
			reasonCode = REASON_CODES.VALIDATION.INVALID_EXPIRY_FORMAT;
		} else if (expiresIn < currentMinPresignedUrlExpirySeconds) {
			const requested = expiresIn;
			expiresIn = currentMinPresignedUrlExpirySeconds;
			error = `Requested 'expires_in_seconds' (${requested}s) is below minimum. Adjusted to ${expiresIn}s.`;
			reasonCode = REASON_CODES.VALIDATION.EXPIRY_TOO_SHORT;
		} else if (expiresIn > currentMaxPresignedUrlExpirySeconds) {
			const requested = expiresIn;
			expiresIn = currentMaxPresignedUrlExpirySeconds;
			error = `Requested 'expires_in_seconds' (${requested}s) exceeds maximum. Adjusted to ${expiresIn}s.`;
			reasonCode = REASON_CODES.VALIDATION.EXPIRY_TOO_LONG;
		}
	} else {
		expiresIn = clientDefaultExpiry; // Use the resolved client default
	}
	return { expiresIn, error, reason_code: reasonCode };
}


async function processPresignRequest(c, currentCleanedPublicUrlPrefix) {
	const DEBUG_MODE = ['true', '1', 'yes'].includes(String(c.env.DEBUG_LOGGING).toLowerCase());
	if (DEBUG_MODE) console.log("Starting processPresignRequest...");

	const { client: s3Client, r2BaseUrl, error: s3ClientError, reason_code: s3ClientErrorReason } = getS3ClientInternal(c);

	if (s3ClientError || !s3Client || !r2BaseUrl) {
		if (DEBUG_MODE) console.error(`S3 client initialization failed or not available: ${s3ClientError}`);
		// This error will be caught by the global error handler if it's not already an HTTPException
		throw new HTTPException(500, {
			message: s3ClientError || "S3 client is not available.",
			problemType: PROBLEM_TYPES.S3_CLIENT_INIT_FAILURE,
			problemTitle: "S3 Client Error",
			reasonCode: s3ClientErrorReason || REASON_CODES.RUNTIME.S3_CLIENT_INIT_FAILURE,
		});
	}

	let requestBody;
	try {
		requestBody = await c.req.json();
	} catch (e) {
		if (DEBUG_MODE) console.error("Failed to parse JSON body:", e);
		throw new HTTPException(400, {
			message: "Malformed JSON in request body.",
			problemType: PROBLEM_TYPES.MALFORMED_REQUEST_BODY,
			problemTitle: "Malformed JSON",
			reasonCode: REASON_CODES.STRUCTURAL.MALFORMED_REQUEST_BODY,
		});
	}

	const { files: filesArray, presign_options: requestPresignOptions } = requestBody;

	if (!Array.isArray(filesArray)) {
		throw new HTTPException(400, {
			message: "'files' array is missing or not an array in the request body.",
			problemType: PROBLEM_TYPES.MISSING_PARAMETER,
			problemTitle: "Missing Parameter",
			reasonCode: REASON_CODES.STRUCTURAL.MISSING_FILES_ARRAY,
		});
	}

	const maxFiles = getMaxFiles(c.env);
	if (filesArray.length === 0) {
		throw new HTTPException(400, {
			message: "'files' array cannot be empty.",
			problemType: PROBLEM_TYPES.VALIDATION_FAILED,
			problemTitle: "Validation Failed",
			reasonCode: REASON_CODES.VALIDATION.INVALID_PARAMETER, 
		});
	}

	if (filesArray.length > maxFiles) {
		throw new HTTPException(400, {
			message: `Too many files requested. Maximum allowed is ${maxFiles}.`,
			problemType: PROBLEM_TYPES.VALIDATION_FAILED,
			problemTitle: "Too Many Files",
			reasonCode: REASON_CODES.STRUCTURAL.TOO_MANY_FILES,
		});
	}


	const expiryDetails = getPresignedUrlExpirySeconds(c, requestPresignOptions);
	if (expiryDetails.error) { 
		// The helper function itself doesn't throw, but signals an issue.
		// We will throw here to make it a formal RFC 7807 error response.
		// Though, in current implementation, it adjusts and returns a value rather than purely erroring.
		// This block handles cases where `expires_in_seconds` was invalid and adjusted, logging the detail.
		// If the logic in getPresignedUrlExpirySeconds changes to *only* error without adjusting,
		// this throw becomes more critical. For now, it's more of a notification if an adjustment happened.
		if (DEBUG_MODE) console.warn(`Presigned URL expiry issue: ${expiryDetails.error}, Code: ${expiryDetails.reason_code}`);
		// We don't necessarily throw if an adjustment was made, because a value is still returned.
		// However, if it were a critical error where NO valid expiry could be determined, we would throw.
		// The current `getPresignedUrlExpirySeconds` always returns a usable `expiresIn` value.
		// So, we will proceed with `expiryDetails.expiresIn`.
		// If a future version of getPresignedUrlExpirySeconds could return NO expiresIn, this logic needs adjustment.
	}
	const effectiveExpirySeconds = expiryDetails.expiresIn; // Use the numeric value


	const presignTasks = [];
	const initialValidationResults = [];

	for (const fileEntry of filesArray) {
		if (typeof fileEntry !== 'object' || fileEntry === null) {
			initialValidationResults.push({
				success: false,
				original_filename: fileEntry?.filename || "N/A (Malformed Entry)",
				detail: 'Each entry in "files" must be an object.',
				reason_code: REASON_CODES.STRUCTURAL.MALFORMED_ENTRY,
			});
			continue;
		}
		// Pass cache_control from fileEntry to validation
		const fileMeta = validateAndGetFileDetails(fileEntry.filename, fileEntry.type, fileEntry.cache_control);
		initialValidationResults.push(fileMeta);

		if (fileMeta.success) {
			presignTasks.push({ fileMeta }); // Keep validated fileMeta for the task
		}
	}

	// Combine initial validation failures with any presign failures later
	const allResults = [...initialValidationResults.filter(r => !r.success)];
	let successfulPresigns = 0;

	if (presignTasks.length > 0) {
		const presignConcurrencyLimit = getPresignRequestConcurrencyLimit(c.env);
		const taskPromises = presignTasks.map(({ fileMeta }) => { // Destructure fileMeta here
			const presignTimeoutMs = getPresignOperationTimeoutMs(c.env);

			const actualPresignOperation = async () => {
				try {
					// fileMeta now contains content_type and cache_control_header
					const { content_type: contentType, extension, upload_folder: uploadFolder, cache_control_header: cacheControlHeader } = fileMeta;
					const r2Key = `${uploadFolder}/${crypto.randomUUID()}.${extension}`;

					const headersToSignAndSend = {
						'Content-Type': contentType,
						'Cache-Control': cacheControlHeader,
						'If-None-Match': '*',
					};

					// Construct the URL for the R2 object, including X-Amz-Expires for query string signing.
					const presignUrlTarget = new URL(`${r2BaseUrl}/${c.env.R2_BUCKET_NAME}/${r2Key}`);
					presignUrlTarget.searchParams.set('X-Amz-Expires', String(effectiveExpirySeconds));

					const requestToSign = new Request(
						presignUrlTarget.toString(), // URL now includes X-Amz-Expires
						{
							method: 'PUT',
							headers: headersToSignAndSend,
						}
					);

					// Sign the request for query string authentication.
					// The X-Amz-Expires is part of the URL's query string and will be included in the signature.
					const signedRequest = await s3Client.sign(requestToSign, {
						aws: { 
							signQuery: true,
							// No 'expires' or 'expiresIn' property here, as it's in the URL's query string.
						},
						// No top-level 'expiresIn' here either.
					});

					const presignedUrl = signedRequest.url;
					const publicAccessUrl = `${currentCleanedPublicUrlPrefix}/${r2Key}`;

					return {
						success: true,
						original_filename: fileMeta.original_filename,
						upload_type: fileMeta.upload_type,
						r2_key: r2Key,
						content_type: contentType,
						upload_url: presignedUrl,
						public_url: publicAccessUrl,
						method: 'PUT',
						headers_to_include: { 
							'Content-Type': contentType,
							'Cache-Control': cacheControlHeader,
							'If-None-Match': '*',
						},
						expires_at: new Date(Date.now() + effectiveExpirySeconds * 1000).toISOString(),
					};
				} catch (presignError) {
					if (DEBUG_MODE) console.error(`S3 presign error for ${fileMeta.original_filename} (key: generated R2 key): ${presignError.message}`, presignError);
					return {
						success: false,
						original_filename: fileMeta.original_filename,
						detail: `Failed to generate presigned URL for ${fileMeta.original_filename}: ${presignError.message}`,
						reason_code: REASON_CODES.RUNTIME.PRESIGN_API_ERROR,
					};
				}
			};

			const timeoutErrorFactoryWithFilename = () => ({
				success: false,
				original_filename: fileMeta.original_filename,
				detail: `Timeout generating presigned URL for ${fileMeta.original_filename}.`,
				reason_code: REASON_CODES.RUNTIME.PRESIGN_TIMEOUT,
				timeout: true,
			});

			return promiseWithTimeout(actualPresignOperation(), presignTimeoutMs, timeoutErrorFactoryWithFilename);
		});

		const settledTasks = await limitedConcurrency(taskPromises.map(p => () => p), presignConcurrencyLimit);


		settledTasks.forEach(result => {
			if (result.status === 'fulfilled') {
				allResults.push(result.value);
				if (result.value.success) {
					successfulPresigns++;
				}
			} else { // status === 'rejected' (likely from timeoutErrorFactory or an unexpected error in actualPresignOperation)
				// The timeoutErrorFactory already shapes the error object.
				// If it's another unexpected rejection, ensure it has a somewhat consistent shape.
				const errorValue = result.reason;
				allResults.push({
					success: false,
					original_filename: errorValue?.original_filename || 'N/A (Rejected Task)',
					detail: errorValue?.detail || errorValue?.message || 'Presign task failed unexpectedly.',
					reason_code: errorValue?.reason_code || REASON_CODES.RUNTIME.UNEXPECTED_PROCESSING_ERROR,
					timeout: errorValue?.timeout || false,
				});
			}
		});
	}

	if (successfulPresigns === 0 && allResults.length > 0) {
		const errorsObject = allResults.reduce((acc, errDetail) => {
			const key = String(errDetail.original_filename || `unknown_file_${Math.random().toString(36).substring(2,7)}`);
			acc[key] = errDetail.detail || 'An unspecified error occurred for this file.';
			return acc;
		}, {});

		throw new HTTPException(422, { 
			message: "All files failed processing. See 'errors' for details.",
			problemType: PROBLEM_TYPES.VALIDATION_FAILED,
			problemTitle: "Processing Failed",
			reasonCode: REASON_CODES.RUNTIME.UNEXPECTED_PROCESSING_ERROR,
			errors: errorsObject,
		});
	}

	// If every single result succeeded, send 200
	// (Assumes allResults.length > 0 at this point, as an empty filesArray is a 400,
	// and all files failing to validate before presign would be caught by the 422 above)
	if (allResults.length > 0 && allResults.every(r => r.success)) {
	  return c.json({ results: allResults }, 200);
	}

	// Otherwise, it's partial success (not all failed, not all succeeded) -> 207 Multi-Status
	// This also covers the theoretical case where allResults might be empty if not caught by earlier checks,
	// though this should be prevented by input validation (empty filesArray -> 400) or the 422 above.
	return c.json({
		results: allResults
	}, 207);
}


app.post('/generate-presigned-urls', async (c) => {
	const publicUrlPrefix = c.env.R2_PUBLIC_URL_PREFIX;
	if (!publicUrlPrefix) {
		console.error("CRITICAL: R2_PUBLIC_URL_PREFIX is not set in environment.");
		throw new HTTPException(500, {
			message: 'Public URL prefix not configured.',
			problemType: PROBLEM_TYPES.INTERNAL_SERVER_ERROR,
			problemTitle: 'Configuration Error',
			reasonCode: REASON_CODES.RUNTIME.INTERNAL_SERVER_ERROR,
		});
	}
	const cleanedPublicUrlPrefix = publicUrlPrefix.replace(TRAILING_SLASH_REGEX, '');
	return processPresignRequest(c, cleanedPublicUrlPrefix);
});


export default app;

