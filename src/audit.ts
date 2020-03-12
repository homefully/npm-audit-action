import * as core from '@actions/core'
import {spawn} from 'child_process'
import stripAnsi from 'strip-ansi'

export class Audit {
  stdout: string = ''
  private status: number | null = null

  public async run(): Promise<void> {
    const result = spawn('npm', ['audit', '--json'], {
      stdio: 'pipe'
    })

    let stdout = ''

    result.stdout.on('data', data => {
      stdout += data.toString()
    })

    result.stderr.on('data', data => {
      core.error(data.toString())
    })

    this.status = await new Promise((resolve, reject) => {
      result.on('close', status => {
        resolve(status)
      })
      result.on('error', status => {
        reject(status)
      })
    })

    this.stdout = stdout.toString()
  }

  public foundVulnerability(): boolean {
    // `npm audit` return 1 when it found vulnerabilities
    return this.status === 1
  }

  public strippedStdout(): string {
    return `\`\`\`\n${stripAnsi(this.stdout)}\n\`\`\``
  }
}
