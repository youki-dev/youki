# Release

youki is released about once a month.
The [release reminder](https://github.com/youki-dev/youki/blob/main/.github/workflows/release-reminder.yaml) workflow asks the release captain to release.

- The workflow runs every Monday at 00:00 UTC.
- It asks when the last release was 28 or more days ago, counted by UTC date.
- If nobody releases, it asks the same captain again 28 days later.

To skip a release, leave the release PR open and write the reason in a comment.
You can release at any time without the reminder.
The next reminder counts the days from that release.

The release captains take turns in this order, one for each release.

- [@utam0k](https://github.com/utam0k)
- [@saku3](https://github.com/saku3)
- [@nayuta723](https://github.com/nayuta723)

To change the captains, update this list and `CAPTAINS` in the workflow.

## Release a new version

tagpr keeps the [release PR](https://github.com/youki-dev/youki/pulls?q=is%3Apr+is%3Aopen+label%3Atagpr) up to date with `main`.

1. Check the version in the title of the release PR.
   tagpr makes a minor release when a merged PR has the `breaking change` label, and a patch release otherwise.
   If the version is wrong, add the `tagpr:minor` label to the release PR.
   tagpr updates the title and the crate versions in the release PR on the next push to `main`.
2. When the title shows the right version, approve and merge the release PR.
   tagpr pushes the tag, and the tag starts the [release workflow](https://github.com/youki-dev/youki/actions/workflows/release.yaml).
3. In the release workflow run, click **Review deployments**, select `release`, and click **Approve and deploy**.
   The workflow publishes the crates to crates.io and then publishes the GitHub release.

If the release workflow fails, re-run the failed jobs.
The workflow reuses the draft release and skips the crates that are already on crates.io.
