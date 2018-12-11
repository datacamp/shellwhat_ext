# shellwhat_ext

[![Build Status](https://travis-ci.org/datacamp/shellwhat_ext.svg?branch=master)](https://travis-ci.org/datacamp/sqlwhat_ext)
[![codecov](https://codecov.io/gh/datacamp/shellwhat_ext/branch/master/graph/badge.svg)](https://codecov.io/gh/datacamp/shellwhat_ext)
[![PyPI version](https://badge.fury.io/py/shellwhat-ext.svg)](https://badge.fury.io/py/shellwhat-ext)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fdatacamp%2Fshellwhat_ext.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fdatacamp%2Fshellwhat_ext?ref=badge_shield)

Extensions to [shellwhat](http://github.com/datacamp/shellwhat) testing.

## Including in a DataCamp course

In the course's `requirements.sh`, add

```
# replace 0.0.1 with the appropriate release version
pip3 install --no-deps shellwhat-ext==0.0.1
```

To use the extensions in an exercise's SCT, import the function you want into the SCT block of the exercise:

```python
from shellwhat_ext import test_cmdline
Ex() >> test_cmdline([['wc',   'l', '+']])
```

## Deploying to PyPI

Follow these steps

1. Open a PR, merge into master when appropriate.
2. Once merged, increment `__version__ = 0.0.1` to reflect changes ([see semver for guidance](http://semver.org/)).
3. Create a github release labeled `vVERSION`. E.g. `v0.0.1`. (see [here](https://help.github.com/articles/creating-releases/)).

## Running tests

```
make install
make test
```



## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fdatacamp%2Fshellwhat_ext.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fdatacamp%2Fshellwhat_ext?ref=badge_large)