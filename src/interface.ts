export interface IssueOption {
  title: string
  body: string
  assignees?: string[]
  labels?: string[]
}

export interface AuditOutput {
  advisories: {
    [x: number]: {
      id: number
      created: string
      updated: string
      title: string
      module_name: string
      cves: []
      vulnerable_versions: string
      patched_versions: string
      overview: string
      recommendation: string
      references: string
      access: string
      severity: string
      cwe: string
      metadata: {
        module_type: string
        exploitability: number
        affected_components: string
      }
      url: string
    }
  }
}
