/* eslint-disable @typescript-eslint/camelcase */
import * as core from '@actions/core'
import * as github from '@actions/github'
import Octokit from '@octokit/rest'
import {Audit} from './audit'
import {AuditOutput} from './interface'

export async function run(): Promise<void> {
  try {
    // run `npm audit`
    const audit = new Audit()
    await audit.run()

    if (audit.foundVulnerability()) {
      core.info("Found vulnarebilities")
      // vulnerabilities are found

      // get GitHub information
      const ctx = JSON.parse(core.getInput('github_context'))
      const token: string = core.getInput('github_token', {required: true})
      const client: Octokit = new github.GitHub(token)

      const auditOutput: AuditOutput = JSON.parse(audit.stdout)
      const advisories = auditOutput.advisories

      const {data: issues} = await client.issues.listForRepo({
        ...github.context.repo
      })

      const promises = Object.values(advisories).map(async advisory => {
        core.info(`Found advisory: ${advisory.id}`)
        const issueName = `${advisory.severity}: ${advisory.title} in ${advisory.module_name} - advisory ${advisory.id}`
        const existingIssue = issues.find(it => it.title === issueName)
        if (existingIssue) {
          core.info('Found issue for advisory')
          return existingIssue
        }

        const createIssue = {
          title: issueName,
          body: `
# npm audit found
${advisory.overview},

*vulnerable versions*: ${advisory.vulnerable_versions},

*fixed in*: ${advisory.patched_versions},

*reference*: ${advisory.references}

*url*: ${advisory.url}
            `
        }

        core.info(`Creating issue for advisory`)
        return (
          await client.issues.create({
            ...github.context.repo,
            ...createIssue
          })
        ).data
      })

      const issuesCreated = await Promise.all(promises)
      core.info(JSON.stringify(issuesCreated, null,4))
      if (issuesCreated.length > 0) {
        core.info(`Found Issues`)
        if (ctx.event_name === 'pull_request') {
          const {data: comments} = await client.issues.listComments({
            owner: github.context.repo.owner,
            repo: github.context.repo.repo,
            issue_number: ctx.event.id
          })

          const commentText = `# Found npm audit issues
${issuesCreated.map(it => `[${it.title}](${it.url})`).join('\n')}
          `
          const foundComment = comments.find(it =>
            it.body.includes('# Found npm audit issues')
          )

          if (foundComment) {
            core.info(`Updating PR comment`)
            await client.issues.updateComment({
              ...github.context.repo,
              comment_id: foundComment.id,
              body: commentText
            })
            return
          }
          core.debug(`Posting PR comment`)

          await client.issues.createComment({
            ...github.context.repo,
            issue_number: ctx.event.id,
            body: commentText
          })

          return
        }
      }
    }
  } catch (error) {
    core.setFailed(error.message)
  }
}

run()
