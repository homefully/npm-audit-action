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

      const prs = await getPRs(client)

      const promises = Object.values(advisories).map(async advisory => {
        core.info(`Found advisory: ${advisory.id}`)
        const issueIdentifier = `advisory ${advisory.id}`
        const issueName = `${advisory.severity}: ${advisory.title} in ${advisory.module_name} - ${issueIdentifier}`
        const existingIssue = issues.find(it =>
          it.title.includes(issueIdentifier)
        )
        const body = `
${advisory.overview},

### vulnerable versions
\`${advisory.vulnerable_versions}\`

### fixed in
\`${advisory.patched_versions}\`

### reference
${advisory.references}

### url
${advisory.url}
            `
        if (existingIssue) {
          core.info('Found issue for advisory')
          return (
            await client.issues.update({
              ...github.context.repo,
              issue_number: existingIssue.number,
              body
            })
          ).data
        }

        const createIssue = {
          title: issueName,
          body
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

      core.info('updating issues with reference to prs')
      for (const issue of issuesCreated) {
        core.info(`updating issue ${issue.number}`)

        for (const pr of prs) {
          core.info(`to reference pr ${pr.number}`)

          const text = `affects [${pr.title}](${pr.html_url})`

          const {data: comments} = await client.issues.listComments({
            ...github.context.repo,
            issue_number: issue.number
          })

          if (comments.find(it => it.body === text) === undefined) {
            await client.issues.createComment({
              ...github.context.repo,
              issue_number: issue.number,
              body: text
            })
          }
        }
      }

      const issueLinks = issuesCreated.map(
        it => `[${it.title}](${it.html_url})`
      )

      if (ctx.event_name === 'pull_request') {
        await postStatusToPr(
          client,
          {
            ...github.context.repo,
            ...ctx.event.id
          },
          issueLinks
        )
      }

      core.info(github.context.ref)
      const {
        data: pulls
      } = await client.repos.listPullRequestsAssociatedWithCommit({
        ...github.context.repo,
        commit_sha: github.context.sha
      })

      for (const pull of pulls) {
        core.info(`checking pr ${pull.number}`)
        await postStatusToPr(
          client,
          {...github.context.repo, issue_number: pull.number},
          issueLinks
        )
      }
    }
  } catch (error) {
    core.setFailed(error.message)
    core.setFailed(error)
  }
}

async function getPRs(
  client: Octokit
): Promise<
  {
    number: number
    title: string
    html_url: string
  }[]
> {
  const {data: pulls} = await client.repos.listPullRequestsAssociatedWithCommit(
    {
      ...github.context.repo,
      commit_sha: github.context.sha
    }
  )
  return pulls
}

async function postStatusToPr(
  client: Octokit,
  prData: {
    owner: string
    repo: string
    issue_number: number
  },
  issues: string[]
): Promise<void> {
  const prCommentText = `# Found npm audit issues
${issues.join('\n')}
`

  core.info('getting comments for pr')
  const {data: comments} = await client.issues.listComments({
    ...prData
  })

  core.info('searching for audit comment')
  const foundComment = comments.find(it =>
    it.body.includes('# Found npm audit issues')
  )

  if (issues.length === 0) {
    if (foundComment) {
      await client.issues.deleteComment({
        ...prData,
        comment_id: foundComment.id
      })
      return
    }
  }

  if (foundComment) {
    core.info(`Updating PR comment for pr: ${prData.issue_number}`)
    await client.issues.updateComment({
      ...prData,
      comment_id: foundComment.id,
      body: prCommentText
    })
    return
  }
  core.info(`Posting PR comment for pr: ${prData.issue_number}`)

  await client.issues.createComment({
    ...prData,
    body: prCommentText
  })

  return
}

run()
