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
      core.info('Found vulnarebilities')
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
      if (issuesCreated.length > 0) {
        const prCommentText = `# Found npm audit issues
${issuesCreated.map(it => `[${it.title}](${it.url})`).join('\n')}
          `

        if (ctx.event_name === 'pull_request') {
          await postStatusToPr(
            client,
            {
              ...github.context.repo,
              ...ctx.event.id
            },
            prCommentText
          )
        }

        core.info(github.context.ref)
        const {
          data: pulls
        } = await client.repos.listPullRequestsAssociatedWithCommit({
          ...github.context.repo,
          commit_sha: github.context.ref
        })

        for (const pull of pulls) {
          core.info(`checking pr ${pull.id}`)
          await postStatusToPr(
            client,
            {...github.context.repo, issue_number: pull.number},
            prCommentText
          )
        }
      }
    }
  } catch (error) {
    core.setFailed(error.message)
  }
}

async function postStatusToPr(
  client: Octokit,
  prData: {
    owner: string
    repo: string
    issue_number: number
  },
  text: string
): Promise<void> {
  core.info('getting comments for pr')
  const {data: comments} = await client.issues.listComments({
    ...prData
  })

  core.info('searching for audit comment')
  const foundComment = comments.find(it =>
    it.body.includes('# Found npm audit issues')
  )

  if (foundComment) {
    core.info(`Updating PR comment for pr: ${prData.issue_number}`)
    await client.issues.updateComment({
      ...prData,
      comment_id: foundComment.id,
      body: text
    })
    return
  }
  core.info(`Posting PR comment for pr: ${prData.issue_number}`)

  await client.issues.createComment({
    ...prData,
    body: text
  })

  return
}

run()
