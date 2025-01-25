# This Documentation

This documentation is created using mdbook and aims to provide a concise reference for users and developers of youki. For more information on mdbook itself, you can check out the [mdbook documentation](https://rust-lang.github.io/mdBook/).

Please make sure that you update this documentation along with newly added features and resources that you found helpful while developing, so that it will be helpful for newcomers.

Currently this documentation is hosted at [https://youki-dev.github.io/youki/](https://youki-dev.github.io/youki/), using GitHub pages. GitHub CI actions are used to automatically check if any files are changed in /docs on each push / PR merge to main branch, and if there are any changes, the mdbook is build and deployed to gh-pages. We use [https://github.com/peaceiris/actions-mdbook](https://github.com/peaceiris/actions-mdbook) to build and then [https://github.com/peaceiris/actions-gh-pages](https://github.com/peaceiris/actions-gh-pages) GitHub action to deploy the mdbook.

When testing locally you can manually test the changes by running `mdbook serve` in the docs directory (after installing mdbook), which will temporarily serve the mdbook at `localhost:3000` by default. You can check the mdbook documentation for more information.

If you want to test it using gh-pages on your own fork, you can use following steps in the docs directory.

```console
git worktree prune
# Do this if you are running this command first time after booting,
# As after shutdown /tmp files are removed
git branch -D gh-pages && git worktree add /tmp/book -b gh-pages
mdbook build
rm -rf /tmp/book/* # this won't delete the .git directory
cp -rp book/* /tmp/book/
cd /tmp/book
git add -A
git commit 'new book message'
git push -f origin gh-pages
cd -
```
