# shellwhat_ext

Extensions to [shellwhat][http://github.com/datacamp/shellwhat] testing.

---

## Design of `test_cmdline`.

`test_cmdline` is used to test what learners typed on a shell command line.
It is more sophisticated than using regular expressions,
but simpler than parsing the user's input and check the AST.
Its design draws on Python's `optparse` library.
Its syntax is:

```
def test_cmdline(pattern, redirect=None, msg='Error')
```

where `pattern` is a pattern that the command line has to match,
`redirect` optionally specifies that redirection to a file is present,
and `msg` is the error message if the match fails.
For example:

```
test_cmdline([['wc',   'l', '+'],
	      ['sort', 'nr'],
	      ['head', 'n:', None, {'n' : 3}]],
	     redirect=r'.+\.txt',
             msg='Incorrect command line')
```

will check command lines of the form:

```
wc -l a.txt b.txt | sort -n -r | head -n 3 > result.txt
```

`test_cmdline` works by tokenizing the actual command line (called `student` below),
checking that each chunk of the result matches the corresponding chunk of `pattern`,
and then checking that any extra constraints are also satisfied.

`pattern` is a list of lists that obeys the following rules:

1. If `redirect` is not `None`,
   then `student` must end with a redirection `>` and a filename,
   and the filename must match the regular expression provided.

1. Each element `pattern` must be a sublist of one or more elements.

1. Each sublist must start with a command name (such as `wc` or `ls`),
   and must match the corresponding element of `student` after splitting on `|` symbols.

1. If the sublist contains a second element,
   it must either be `None` (meaning "no command-line parameters accepted")
   or an `optparse`-style argument specification (see below).
   An empty string is *not* allowed.

1. If the sublist contains a third element,
   it must be `None` (indicating that no trailing filenames are allowed),
   `+` (indicating that one or more trailing filenames must be present),
   or `*` (indicating that zero or more trailing filenames are allowed).

1. If the sublist contains a fourth element,
   it must be a dictionary whose keys match command parameters
   and whose values are either simple values (which must match exactly),
   regular expressions (which must match),
   or functions (which must return `True`).

The `optparse`-stye spec consists of one or more letters,
each of which may optionally be followed by `:` to indicate that it takes an argument.
For example, `nr` indicates that `-n` and `-r` must appear,
but can appear in any order,
while `n:` indicates that `-n` must appear and must be followed by an argument.
Thus,
the pattern in the example above:

```
[['wc',   'l', '+'],
 ['sort', 'nr'],
 ['head', 'n:', None, {'n' : 3}]]
```

matches:

- `wc`, `-l` without parameters, and one or more trailing filenames,
- `sort` with both `-n` and `-r` (in either order) but no trailing filenames, and
- `head` with `-n value`, where `value` must equal the integer 3.

Notes:

1. `test_cmdline` uses a list of lists rather than a dictionary mapping command names to specs
   because we need to specify the order of commands,
   and because a command may appear twice in one pipeline.

1. `test_cmdline` starts by checking that the number of piped commands
    matches the length of the pattern specification,
    and reports an error if it does not.
