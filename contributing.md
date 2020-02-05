# Contributing to SELint

Thanks for your interest in contributing!  You can find helpful tips and guidelines for contributing below.

## How Can I Contribute?

### Reporting Bugs

See something wrong with SELint?  Please let us know by filing a bug in the Issue Tracker.

Before creating a bug, check the issue tracker to see if your issue has already been reported.  When reporting the issue, please provide enough information to allow developers to reproduce the problem, including simple policy snippets that reveal the issue where possible.  Don't forget to include your distro, SELint version, command line flags you ran SELint with, and any relevant configuration.

### Suggesting enhancements

Feel free to submit requests for new features or additional policy checks.  If submitting a check, please provide an example of compliant and non-compliant policy on that issue.

## Contributing Code

### Installing the latest source

Make sure you're working against the latest source by checking out github master.  In order to build the full project with autotools, you'll need to install the autoconf-archive package and then run ./autogen.sh.  Then you can follow the instructions in the README for building from a release tarball.

### Submitting your code

Please submit contributions via github PR.  This is set up to run automated tests against all changes.  If submitting code doing multiple different things, please break PRs up so each PR contains one logical change.  (For example, if you were adding a new check and also found and fixed a bug with another check along the way, please submit separate PRs for each).

### Getting Started

If you're looking for a place to start learning the code base, I recommend either fixing a bug from the issue tracker (check for the "good first issue" label for easy places to start), or adding a new check.

When fixing a bug, please let a maintainer know that you're working on it so we can assign it to you and other developers know not to duplicate effort.  If it takes you a while, that's fine, but please provide regular updates in the ticket, so we know you're still working and haven't abandoned it.

### Adding checks

One of SELint's design goals is to make it straightforward for new developers to add checks.

The first thing to do is to decide where to put your check.  Checks live in te\_checks.{c,h}, if\_checks.{c,h}, and fc\_checks.{c,h}.  While your check will apply to all three kinds of files where applicable, this provides some level of logical organization.  If your check is about typical policy rules that can occur in both .te files or inside interfaces, put it in te\_checks; if it is about something specific to interfaces or file contexts, put it in if\_checks or fc\_checks respectively.

Your check should have the following prototype:

`struct check_result *check_function(const struct check_data * data, const struct policy_node * node);`

In order to allow your check to be run, you need to add it to the register\_checks() function in runner.h, where you specify the type of node you should be run on, as well as the Check ID number, and your check function.

Please also include unit tests for your check and update the README and check\_examples.txt
