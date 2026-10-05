import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { isActive, uploadFile } from '@/api/uploads'
import { HttpError } from '@/lib/queryClient'

/** Minimal stand-in for the browser's XMLHttpRequest: records the request, lets tests reply. */
class FakeXhr {
  static last: FakeXhr
  method = ''
  url = ''
  body: FormData | null = null
  responseType = ''
  status = 0
  statusText = ''
  response: unknown = null
  upload: { onprogress: ((e: { lengthComputable: boolean; loaded: number; total: number }) => void) | null } = {
    onprogress: null,
  }
  onload: (() => void) | null = null
  onerror: (() => void) | null = null

  constructor() {
    FakeXhr.last = this
  }
  open(method: string, url: string) {
    this.method = method
    this.url = url
  }
  send(body: FormData) {
    this.body = body
  }
  // test helpers
  progress(loaded: number, total: number) {
    this.upload.onprogress?.({ lengthComputable: true, loaded, total })
  }
  reply(status: number, response: unknown, statusText = '') {
    Object.assign(this, { status, response, statusText })
    this.onload?.()
  }
}

const realXhr = globalThis.XMLHttpRequest
beforeEach(() => {
  globalThis.XMLHttpRequest = FakeXhr as unknown as typeof XMLHttpRequest
})
afterEach(() => {
  globalThis.XMLHttpRequest = realXhr
})

const file = () => new File(['time,user\n'], 'proxy.log', { type: 'text/plain' })

describe('uploadFile', () => {
  it('POSTs the file, timezone and format as multipart form data', () => {
    void uploadFile(file(), 'America/New_York', 'json', () => {})
    const xhr = FakeXhr.last

    expect([xhr.method, xhr.url, xhr.responseType]).toEqual(['POST', '/api/uploads', 'json'])
    expect((xhr.body?.get('file') as File).name).toBe('proxy.log')
    expect(xhr.body?.get('log_timezone')).toBe('America/New_York')
    expect(xhr.body?.get('format')).toBe('json')
  })

  it('reports upload progress as a fraction', () => {
    const seen: number[] = []
    void uploadFile(file(), 'UTC', 'auto', (f: number) => seen.push(f))

    FakeXhr.last.progress(25, 100)
    FakeXhr.last.progress(100, 100)

    expect(seen).toEqual([0.25, 1])
  })

  it('resolves with the created upload on 201', async () => {
    const promise = uploadFile(file(), 'UTC', 'auto', () => {})
    FakeXhr.last.reply(201, { id: 7, status: 'queued' })

    await expect(promise).resolves.toMatchObject({ id: 7, status: 'queued' })
  })

  it.each([
    [400, { detail: "Doesn't look like a Zscaler CSV: line 1: Expected 20 columns, got 2" }],
    [413, { detail: 'File is larger than 1024 MB' }],
    [401, { detail: 'Not authenticated' }],
  ])('rejects with HttpError carrying status %i and the server message', async (status, body) => {
    const promise = uploadFile(file(), 'UTC', 'auto', () => {})
    FakeXhr.last.reply(status, body)

    const error = await promise.catch((e: unknown) => e)
    expect(error).toBeInstanceOf(HttpError)
    expect((error as HttpError).status).toBe(status)
    expect((error as HttpError).message).toBe(body.detail)
  })

  it('rejects with status 0 when the network fails', async () => {
    const promise = uploadFile(file(), 'UTC', 'auto', () => {})
    FakeXhr.last.onerror?.()

    await expect(promise).rejects.toMatchObject({ status: 0, message: "Can't reach the server" })
  })
})

describe('isActive', () => {
  it('is true only while queued or processing (drives polling)', () => {
    expect(['queued', 'processing', 'done', 'failed'].map(isActive)).toEqual([true, true, false, false])
  })
})
