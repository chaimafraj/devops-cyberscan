import { HttpErrorResponse } from '@angular/common/http';

export interface ApiError {
  status: number;
  code: string;
  message: string;
  details?: unknown;
}

export interface ApiMessage {
  message: string;
}

export interface PaginatedResponse<T> {
  results: T[];
  count: number;
  total_pages?: number;
  current_page?: number;
  total?: number;
  page?: number;
}

export function toApiError(error: unknown, fallback = 'Une erreur est survenue.'): ApiError {
  if (!(error instanceof HttpErrorResponse)) {
    return { status: 0, code: 'UNKNOWN_ERROR', message: fallback, details: error };
  }
  const body: unknown = error.error;
  const record = isRecord(body) ? body : {};
  const message = firstString(record['error'], record['detail'], record['message'])
    ?? (typeof body === 'string' ? body : fallback);
  return {
    status: error.status,
    code: firstString(record['code']) ?? 'HTTP_' + (error.status || 0),
    message,
    details: body,
  };
}

function firstString(...values: unknown[]): string | undefined {
  return values.find((value): value is string => typeof value === 'string' && value.length > 0);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

