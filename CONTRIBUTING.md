# How to Contribute to LoT

We'd love your help!

LoT is [Apache License 2.0](LICENSE) and accepts contributions via
GitHub pull requests. This document outlines some of the conventions
on development workflow, commit message formatting, contact points and
other resources to make it easier to get your contributions accepted.

## Project structure

The project currently following structure:

```
.
├── cmd
│   └─<commands/sub-commands>.go
├── pkg
│   └── util
│       ├── bpfutil
│       │   └── all BPF command related files
│       ├── dashboard
│       │   └── all Dashboard command related files
│       ├── diskutil
│       │   └── all Disk command related files
│       ├── netutils
│       │   └── all Network command related files
│       ├── procutil
│       │   └── all Process command related files
│       ├── sysutil
│       │   └── all files related to generic System fucntionalities
│       └── util.go ⟵ contains various utility functions that can be used by multiple packages
└── Rest of files(README, Makefile, main.go, go.mod, go.sum, etc)
```

## Making A Change

* _Before making any significant changes, please [open an
issue](https://github.com/infracloudio/lot/issues)._ Discussing
your proposed changes ahead of time will make the contribution process
smooth for everyone.

* Once we've discussed your changes and you've got your code ready,
you can open your pull
request against
[`develop`](http://github.com/infracloudio/lot/tree/develop)
branch.

* To keep things fun we follow the following commit pattern:

```
a random funny commit message typically from https://whatthecommit.com

* The original change description should be added in bullet points as extened commit messages
* Keep each bullet point within 80 or 100 chars(maximum)

Sign-off: Name <email address>
```

* <u>__Make sure that all of your commits are [signed](https://help.github.com/en/articles/signing-commits) and has a [DCO sign-off](https://github.com/apps/dco)__</u>

* It really would be appreciated if your pull requests follow the
same message pattern as the commits with following points also taken care of:
  * Separate subject from body with a blank line
  * Limit the subject line to 60 characters
  * Capitalize the subject line
  * Do not end the subject line with a period
  * Use the imperative mood in the subject line
  * Wrap the body at 80 characters
  * Use the body to explain _what_ and _why_ instead of _how_
  
* Make sure that your pull request addresses a single change and has a single concern only.

* Squash unimportant commits and rebase your changes on to
develop branch, this will make sure we have clean log of changes.
