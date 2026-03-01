# Contribution Guidelines

We welcome many kinds of community contributions to this project! Whether it's a feature implementation,
bug fix, or a good idea, please create an issue so that we can discuss it. It is not necessary to create an
issue before sending a pull request but it may speed up the process if we can discuss your idea before
you start implementing it.

## Ways to Contribute

- File a bug or feature request as an [issue](https://github.com/BatmanAMA/pwssh/issues)
- Comment on existing issues to give your feedback on how they should be fixed/implemented
- Contribute a bug fix or feature implementation by submitting a pull request
- Contribute more unit tests for feature areas that lack good coverage
- Review the pull requests that others submit to ensure they follow [established guidelines](#pull-request-guidelines)

## Code Contribution Guidelines

Here's a high level list of guidelines to follow to ensure your code contribution is accepted:

- Follow established guidelines for coding style and design
- Follow established guidelines for commit hygiene
- Write unit tests to validate new features and bug fixes
- Ensure that `.\build.ps1 -Task Test` passes locally
- Respond to all review feedback and final commit cleanup

### Coding Style

- PowerShell functions use approved verbs (`Get-`, `New-`, `Remove-`, `Invoke-`, etc.)
- All public functions must include comment-based help with Synopsis, Description, Parameters, and Examples
- Use `[CmdletBinding()]` on all functions
- Sensitive data (passwords, keys) must use `[securestring]` or `[pscredential]` parameters — never plain `[string]`
- Wipe any plaintext credential variables in `finally` blocks (`$var = $null`)
- C# code in `SSHCrypto.cs` must wipe all `byte[]` containing key material via `CryptoUtil.Wipe()` or `SecureBuffer`

### Practice Good Commit Hygiene

First of all, make sure you are practicing [good commit hygiene](http://blog.ericbmerritt.com/2011/09/21/commit-hygiene-and-git.html)
so that your commits provide a good history of the changes you are making. To be more specific:

- **Write good commit messages**

  Commit messages should be clearly written so that a person can look at the commit log and understand
  how and why a given change was made. Here is a good model:

      Capitalized, short (50 chars or less) summary

      More detailed explanatory text, if necessary. Wrap it to about 72
      characters or so. The blank line separating the summary from the body
      is critical.

      Write your commit message in the imperative: "Fix bug" and not
      "Fixed bug" or "Fixes bug."

      - Bullet points are okay, too

- **Squash your commits**

  If you are introducing a new feature but have implemented it over multiple commits,
  please [squash those commits](http://gitready.com/advanced/2009/02/10/squashing-commits-with-rebase.html)
  into a single commit that contains all the changes in one place. This especially applies to any "oops"
  commits where a file is forgotten or a typo is being fixed.

- **Keep individual commits for larger changes**

  You can certainly maintain individual commits for different phases of a big change. For example, if
  you want to reorganize some files before adding new functionality, have your first commit contain all
  of the file move changes and then the following commit can have all of the feature additions.

### Follow the Pull Request Process

- **Create your pull request**

  Use the [typical process](https://help.github.com/articles/using-pull-requests/) to send a pull request
  from your fork of the project. In your pull request message, please give a high-level summary of the
  changes that you have made so that reviewers understand the intent of the changes. You should receive
  initial comments within a day or two, but please feel free to ping if things are taking longer than
  expected.

- **Respond to code review feedback**

  If the reviewers ask you to make changes, make them as a new commit to your branch and push them so
  that they are made available for a final review pass. Do not rebase the fixes just yet so that the
  commit hash changes don't upset GitHub's pull request UI.

- **If necessary, do a final rebase**

  Once your final changes have been accepted, we may ask you to do a final rebase to have your commits
  so that they follow our commit guidelines. Once you do your final push, we will merge your changes!
