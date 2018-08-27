import os
import re
from getopt import getopt, GetoptError
from shellwhat.sct_syntax import state_dec

__version__ = '0.4.0'

#-------------------------------------------------------------------------------

# Make re.compile more accessible because it's used so often in tests.
rxc = re.compile

#-------------------------------------------------------------------------------

@state_dec
def test_condition(state, condition, msg):
    '''Check whether a Boolean condition is satisfied, and if not,
    report the error.  This can be used for tests like:

    THIS FUNCTION IS NOT TESTED AND SHOULD BE USED AT OWN RISK.

        test_condition('.filiprc' in os.listdir('/home/repl'),
                       "Home directory does not contain a .filiprc file")
    '''

    if not condition:
        state.do_test(msg)
    return state # all good

#-------------------------------------------------------------------------------

# Copied from shellwhat - should import instead.
ANSI_REGEX = "(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]"
def _strip_ansi(result):
    return re.sub(ANSI_REGEX, '', result)

@state_dec
def test_output_condition(state, condition, msg, strip_ansi = True):
    """Test whether the student's output passes an arbitrary condition.

    THIS FUNCTION IS NOT TESTED AND SHOULD BE USED AT OWN RISK.

    Args:
        state     : State instance describing student and solution code. Can be omitted if used with Ex().
        condition : Lambda of one argument taking the text as input and returning True or False.
        msg       : Feedback message if text does not pass test.
        strip_ansi: whether to remove ANSI escape codes from output.
    """

    stu_output = state.student_result
    if strip_ansi:
        stu_output = _strip_ansi(stu_output)
    return test_condition(state, condition(stu_output), msg)

#-------------------------------------------------------------------------------

@state_dec
def test_file_content_condition(state, path, condition, msg):
    """Test whether the content of a file passes a test.

    THIS FUNCTION IS NOT TESTED AND SHOULD BE USED AT OWN RISK.

    Args:
        state    : State instance.
        path     : Path to file. Function fails if file does not exist.
        condition: Lambda of one argument taking the content of the file as input and returning True or False.
        msg      : Feedback message if text does not pass test.
    """

    try:
        with open(path, 'r') as reader:
            data = reader.read()
            return test_condition(state, condition(data), msg)
    except IOError:
        state.do_test('Unable to open file "{}"'.format(path))

#-------------------------------------------------------------------------------

@state_dec
def test_compare_file_to_file(state, actualFilename, expectFilename, debug=None):
    '''Check if a file is line-by-line equal to another file (ignoring
    whitespace at the start and end of lines and blank lines at the
    ends of files).

    THIS FUNCTION IS NOT TESTED AND SHOULD BE USED AT OWN RISK.
    '''

    actualList = _get_lines_from_file(state, actualFilename)
    expectList = _get_lines_from_file(state, expectFilename)

    actualLen = len(actualList)
    expectLen = len(expectList)
    if actualLen != expectLen:
        msg = 'File {} has wrong length: got {} expected {}'
        msg = msg.format(actualFilename, actualLen, expectLen)
        if debug is not None:
            msg += ' (-( {} )-)'.format(debug)
        state.do_test(msg)

    diffs = []
    for (i, actualLine, expectLine) in zip(range(len(actualList)), actualList, expectList):
        if actualLine != expectLine:
            diffs.append(i+1)

    if diffs:
        msg = 'Line(s) in {} not as expected: {}'
        msg = msg.format(actualFilename, ', '.join([str(x) for x in diffs]))
        if debug is not None:
            msg += ' (-( {} // expect {} // actual {} )-)'.format(debug, str(expectList), str(actualList))
        state.do_test(msg)

    return state # all good

def _get_lines_from_file(state, filename):
    '''Return a list of whitespace-stripped lines from a file, or fail if
    the file cannot be found.  Remove blank lines from the end of the
    file.'''

    try:
        with open(filename, 'r') as stream:
           lines = [x.strip() for x in stream.readlines()]
    except Exception:
        state.do_test('Unable to open file {}'.format(filename))

    while not lines[-1]:
        del lines[-1]

    return lines

#-------------------------------------------------------------------------------

@state_dec
def test_file_perms(state, path, perms, message, debug=None):
    '''Test that something has the required permissions.

    THIS FUNCTION IS NOT TESTED AND SHOULD BE USED AT OWN RISK.
    '''

    if not os.path.exists(path):
        msg = '{} does not exist'.format(path)
        if debug is not None:
            msg += ' (-( {} )-)'.format(debug)
        state.do_test(msg)
    controls = {'r' : os.R_OK, 'w' : os.W_OK, 'x' : os.X_OK}
    flags = 0
    for p in perms:
        flags += controls[p]
    if not os.access(path, flags):
        state.do_test('{} {}'.format(path, message))
    return state

#-------------------------------------------------------------------------------

@state_dec
def test_output_does_not_contain(state,
                                 text,
                                 fixed=True,
                                 msg='Submission output contains "{}", while it shouldn\'t'):
    '''Test that the output doesn't match.'''

    if fixed:
        if text in state.student_result:
            state.do_test(msg.format(text))

    else:
        pat = rxc(text)
        if pat.search(state.student_result):
            state.do_test(msg.format(text))

    return state

#-------------------------------------------------------------------------------

@state_dec
def test_show_student_code(state, msg):
    """Debugging utility to show the student-submitted code. Must be last
    in the chain, since it always fails."""

    state.do_test('{}:\n```\n{}\n```\n'.format(msg, state.student_code))

#-------------------------------------------------------------------------------

@state_dec
def test_show_student_output(state, msg):
    """Debugging utility to show the student's actual output. Must be last
    in the chain, since it always fails."""

    state.do_test('{}:\n```\n{}\n```\n'.format(msg, state.student_result))

#-------------------------------------------------------------------------------    

PAT_TYPE = type(rxc('x'))
PAT_ARGS = rxc('{}|{}|{}'.format(r'[^"\'\s]+', r"'[^']+'", r'"[^"]+"'))

@state_dec
def test_cmdline(state, pattern, redirect=None, incorrect_msg=None, last_line=False, debug=None):
    """
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
            ['head', 'n:', None, {'-n' : '3'}]],
            redirect=re.compile(r'.+\.txt'),
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
    """

    line = _cmdline_select_line(state, last_line)
    actualCommands, actualRedirect = _cmdline_parse(state, line, incorrect_msg, debug=debug)
    _cmdline_match_redirect(state, redirect, actualRedirect, incorrect_msg, debug=debug)
    _cmdline_match_all_commands(state, pattern, actualCommands, incorrect_msg, debug=debug)
    return state


def _cmdline_select_line(state, last_line):
    line = state.student_code.strip()
    if last_line:
        line = line.split('\n')[-1]
    return line


def _cmdline_parse(state, line, msg=None, debug=None):
    stripped, redirect = _cmdline_get_redirect(state, line, msg, debug)
    commands = [_cmdline_parse_command(c.strip()) for c in stripped.strip().split('|')]
    return commands, redirect


def _cmdline_get_redirect(state, text, msg=None, debug=None):

    if '>' not in text:
        return text, None
    if text.count('>') > 1:
        _cmdline_fail(state, 'Command line can contain at most one ">"', msg, debug)

    pre, post = [x.strip() for x in text.split('>')]

    if not pre:
        _cmdline_fail(state, 'Line cannot start with redirection', msg, debug)
    if not post:
        _cmdline_fail(state, 'Dangling ">" at end of line', msg, debug)
    if '|' in post:
        _cmdline_fail(state, 'Cannot redirect to something containing a pipe "{}".format(post)', msg, debug)
    if ' ' in post:
        _cmdline_fail(state, 'Cannot redirect to something containin spaces "{}"'.format(post), msg, debug)

    return pre, post


def _cmdline_match_redirect(state, pattern, actual, msg=None, debug=None):
    if pattern is None:
        if actual:
            _cmdline_fail(state, 'Redirect found when none expected "{}"'.format(actual), msg, debug)
    elif isinstance(pattern, str):
        if pattern != actual:
            _cmdline_fail(state, 'Pattern "{}" does not match actual "{}"'.format(pattern, actual), msg, debug)
    elif type(pattern) == PAT_TYPE:
        if not pattern.search(actual):
            _cmdline_fail(state, 'Regular expression "{}" does not match actual "{}"'.format(pattern.pattern, actual), msg, debug)


def _cmdline_parse_command(text):
    return [_cmdline_strip_quotes(a) for a in PAT_ARGS.findall(text)]


def _cmdline_strip_quotes(val):
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        val = val[1:-1]
    return val


def _cmdline_match_all_commands(state, pattern, actual, msg=None, debug=None):
    if len(pattern) != len(actual):
        _cmdline_fail(state, 'Unexpected number of components in command line: expected "{}" found "{}"'.format(len(pattern), len(actual)), msg, debug)
    for (p, a) in zip(pattern, actual):
        _cmdline_match_command(state, p, a, msg, debug=debug)


def _cmdline_match_command(state, pattern, actual, msg=None, debug=None):

    # Command.
    assert len(pattern) > 0, 'Pattern must have at least a command name'
    assert len(actual) > 0, 'Command cannot be empty'

    # Disassemble pattern.
    pat_cmd, pat_optstring, pat_filespec, pat_constraints = _cmdline_disassemble_pattern(pattern)
    if pat_cmd != actual[0]:
        _cmdline_fail(state, 'Expected command "{}" got "{}"'.format(pat_cmd, actual[0]), msg, debug)

    # No parameters allowed.
    if pat_optstring is None:
        if len(actual) > 1:
            _cmdline_fail(state, 'Pattern does not allow parameters but actual command contains some "{}"'.format(actual), msg, debug)
        return state

    # Get actual flags, their arguments, and trailing filenames.
    try:
        actual_opts, actual_extras = getopt(actual[1:], pat_optstring)
    except GetoptError as e:
        state.do_test(str(e))

    # Check trailing filenames both ways.
    _cmdline_check_filenames(state, pat_cmd, pat_filespec, actual_extras, msg, debug)

    # Check constraints.
    _cmdline_check_constraints(state, pat_cmd, pat_constraints, actual_opts, msg, debug)


def _cmdline_disassemble_pattern(pattern):
    cmd, optstring, filespec, constraints = pattern[0], None, None, None
    if len(pattern) > 1:
        optstring = pattern[1]
    if len(pattern) > 2:
        filespec = pattern[2]
    if len(pattern) > 3:
        constraints = pattern[3]
    assert len(pattern) <= 4, 'Pattern can have at most four elements'
    return cmd, optstring, filespec, constraints


def _cmdline_check_filenames(state, cmd, filespec, extras, msg=None, debug=None):

    # Nothing allowed.
    if filespec is None:
        if extras:
            _cmdline_fail(state, 'Unexpected trailing filenames "{}" for "{}"'.format(extras, cmd), msg, debug)

    # Filespec is a single string '*' (for zero or more) '+' (for one or more) or a filename.
    elif isinstance(filespec, str):
        if filespec == '*':
            pass
        elif filespec == '+':
            if len(extras) == 0:
                _cmdline_fail(state, 'Expected one or more trailing filenames, got none for "{}"'.format(cmd), msg, debug)
        else:
            if len(extras) != 1:
                _cmdline_fail(state, 'Expected one filename "{}", got "{}"'.format(filespec, extras), msg, debug)
            if extras[0] != filespec:
                _cmdline_fail(state, 'Expected filename "{}", got "{}"'.format(filespec, extras[0]), msg, debug)

    # Filespec is a single regular expression.
    elif type(filespec) == PAT_TYPE:
        if len(extras) != 1:
            _cmdline_fail(state, 'Expected one filename for "{}", got "{}"'.format(cmd, extras), msg, debug)
        if not re.search(filespec, extras[0]):
            _cmdline_fail(state, 'Filename "{}" does not match pattern "{}"'.format(extras[0], filespec.pattern), msg, debug)

    # Filespec is a list of strings or regular expressions that must match in order.
    elif isinstance(filespec, list):
        if len(filespec) != len(extras):
            _cmdline_fail(state, 'Wrong number of filename arguments for "{}"'.format(cmd), msg, debug)
        for (f, e) in zip(filespec, extras):
            if isinstance(f, str):
                if f != e:
                    _cmdline_fail(state, 'Filenames differ or not in order in list for command "{}"'.format(cmd), msg, debug)
            elif type(f) == PAT_TYPE:
                if not re.search(f, e):
                    _cmdline_fail(state, 'Filenames differ or not in order in list for command "{}" ("{}" vs pattern "{}")'.format(cmd, e, f), msg, debug)
            else:
                assert False, 'Filespec "{}" not yet supported in list'.format(filespec)

    # Filespec is a set of strings that must match all match (in any order).
    elif isinstance(filespec, set):
        if filespec != set(extras):
            _cmdline_fail(state, 'Filenames differ for command "{}": spec "{}" vs. actual "{}"'.format(cmd, filespec, extras), msg, debug)

    # Filespec isn't supported yet.
    else:
        assert False, 'Filespec "{}" not yet supported'.format(filespec)


def _cmdline_check_constraints(state, cmd, constraints, opts, msg=None, debug=None):
    if constraints is None:
        return
    for (opt, arg) in opts:
        if opt in constraints:
            required = constraints[opt]
            if callable(required):
                if not required(arg):
                    _cmdline_fail(state, 'Argument "{}" of flag "{}" for "{}" failed test'.format(arg, opt, cmd), msg, debug)
            elif type(required) == PAT_TYPE:
                if not required.search(arg):
                    _cmdline_fail(state, 'Argument "{}" of flag "{}" for "{}" does not match pattern "{}"'.format(arg, opt, cmd, required.pattern), msg, debug)
            elif required is None:
                if arg != '':
                    _cmdline_fail(state, 'Flag "{}" for "{}" should not have argument but has {}'.format(opt, cmd, arg), msg, debug)
            elif arg != required:
                _cmdline_fail(state, 'Argument "{}" of flag "{}" for "{}" does not match required "{}"'.format(arg, opt, cmd, required), msg, debug)
            del constraints[opt]
    if constraints:
        _cmdline_fail(state, 'Missing flag(s) for {}: {}'.format(cmd, ', '.join(constraints.keys())), msg, debug)


def _cmdline_fail(state, internal, external, debug = None):
    report = external if external else ''
    if debug:
        report = '{} ({})'.format(report, internal)
    state.do_test(report)


#-------------------------------------------------------------------------------

import re
from getopt import getopt, GetoptError

RE_TYPE = type(rxc(''))
RE_ARGS = rxc('{}|{}|{}'.format(r'[^"\'\s]+', r"'[^']+'", r'"[^"]+"'))

def tc_assert(state, condition, details, *extras):
    '''
    Fail if condition not true. Always report msg; report details if debug
    set in state.
    '''

    if condition:
        return

    if hasattr(state, 'tc_debug') and state.tc_debug:
        state.tc_msg = state.tc_msg + ' :: ' + details.format(*extras)
    state.do_test(state.tc_msg)
    
@state_dec
def test_cmdline_v2(state, spec, msg, redirect_out=None, last_line_only=False, debug=False):
    '''Test command line without fully parsing.

    `test_cmdline_v2` tests a Unix command line containing pipes and output
    redirection against a specification.  An example of its use is:

        test_cmdline_v2(state,
                       [['extract', '', [rxc(r'p.+\.txt'), {'data/b.csv', 'data/a.csv'}]],
                       ['sort', 'n'],
                       ['tail', 'n:', [], {'-n' : '3'}]],
                       'Use extract, sort, and tail with redirection.',
                       redirect_out=re.compile(r'.+\.csv'),
                       last_line_only=True)

    which will correctly match the command line:

        '\n\nextract params.txt data/a.csv data/b.csv | sort -n | tail -n 3 > last.csv\n'

    The required parameters to `test_cmdline_v2` are:

    -   The SCT state object.  If the function is called using
        `Ex().test_cmdline_v2(...)`, this parameter does not have to be supplied.

    -   A list of sub-specifications, each of which matches a single
        command in the pipeline.  The format is described below.

    -   The error message to be presented to the user if the test fails.

    Each sub-spec must have a command name and a getopt-style string
    specifying any parameters it is allowed to take.  The command name
    may be a list of strings as well, to handle things like `git commit`;
    if the optstring is `None`, then no options are allowed.

    The sub-spec may also optionally specify the filenames that are
    expected (including sets if order doesn't matter and regular
    expressions if variant paths are allowed) and a dictionary of
    parameter values for options that take them.  The format of sub-specs
    is described in more detail below.

    The optional named parameters are:

    -   `redirect_out`: where to redirect standard output.

    -   `lastlineOnly`: if `True`, the user text is split on newlines and
        only the last line is checked.  If `False`, the entire user input
        is checked.  This is to handle cases where we need to set shell
        variables or do other things in the sample solution that the user
        isn't expected to do.

    -   `debug`: if `True`, print internal debugging messages when things go
        wrong.

    In the simplest case, the filenames in a sub-spec is a list of actual
    filenames, such as `['a.csv', 'b.csv']`.  However, it may also include
    a *set* of filenames of length N, in which case the next N actual
    filenames must exactly match the elements of the set.  A filespec
    element may also be a regular expression instead of a simple string,
    in which case the pattern and the actual filename must match.  For
    example, the filespec:

        ['params.txt', {'a.csv', 'b.csv'}, re.compile(r'.+\.csv')]

    means:

    -   The first actual filename must be `params.txt`.
    -   The next two filenames must be `a.csv` and `b.csv` in any order.
    -   The last filename must end with `.csv`.
    -   (Implied) there must be exactly four filenames.

    The dictionary argument of a sub-spec maps command flags to strings,
    regular expressions, or functions of a single argument that test the
    argument supplied with the flag.  Flags must be specified as `-n`
    instead of just `n`, and test functions must return `True` or `False`.
    For example, the constraints:

        {'-a' : '5', '-b' : re.compile(r'^\d+$'), 'c' : lambda x: int(x) > 0}

    means:

    -   The argument of `-a` must be the string `5`.
    -   The argument of `-b` must be a non-empty string of digits.
    -   The argument of `-c` must parse to a positive integer.

    Finally, a full command spec's last item may be an instance of the
    class `Optional`, which means "one final command in the pipeline may
    or may not be present".  This is allowed so that `test_cmdline` can
    handle solution code of the form:

        less a.csv | cat

    where the trailing `cat` is needed in the solution to prevent
    automated testing timing out, but won't be present when the student
    enters an actual solution.

    Things which are not handled (or not handled properly):

    -   Correctly-quoted arguments in command lines are handled, but
        incorrectly quoted arguments, or quoted arguments that contain
        the pipe symbol '|', are not handled.

    -   Input redirection is not currently handled.

    -   Appending output with `>>` is not currently handled.

    -   Actual command-line flags and parameters that are not included
        in the optstring spec for a command are ignored.

    To make the code easier to track, the user-supplied error message is
    added as `state.tc_msg`.  This allows us to pass `state` everywhere
    and get what we need.
    '''

    assert spec, 'Empty spec'

    state.tc_debug = debug
    state.tc_msg = msg

    tc_assert(state, state.student_code, 'No student code provided')

    chunks, redirect_actual = tc_parse_cmdline(state, last_line_only)
    tc_check_redirect(state, redirect_out, redirect_actual)
    spec, chunks = tc_handle_optional(state, spec, chunks)
    for (s, c) in zip(spec, chunks):
        tc_check_chunk(state, s, c)

    return state

class Optional(object):
    '''
    Marker class for optional last command in a pipeline.
    '''

    def __init__(self, text='unspecified'):
        self.text = text

def tc_parse_cmdline(state, last_line_only=False):
    '''
    Parse the actual command line, returning a list of |-separated
    chunks and the redirection (if any).
    '''

    line = state.student_code.strip()
    if last_line_only:
        line = line.split('\n')[-1]
    else:
        tc_assert(state, '\n' not in line, 'Command line contains newlines')
    line, redirect = tc_get_redirect(state, line)
    chunks = [tc_parse_chunk(state, line, c.strip()) for c in line.strip().split('|')]
    return chunks, redirect


def tc_get_redirect(state, line):
    '''
    Strip and return any trailing redirection in the actual command line.
    '''

    # No redirection.
    if '>' not in line:
        return line, None

    tc_assert(state, line.count('>') <= 1,
              'Line "{}" contains more than one ">"', line)

    pre, post = [x.strip() for x in line.split('>')]

    tc_assert(state, pre,
              'Line "{}" cannot start with redirection', line)
    tc_assert(state, post,
              'Dangling ">" at end of "{}"', line)
    tc_assert(state, '|' not in post,
              'Line "{}" cannot redirect to something containing a pipe', line)

    return pre, post


def tc_parse_chunk(state, line, section):
    '''
    Parse one of the |-separated chunks of the actual command line
    using regular expressions (which is very fallible, and I should
    be ashamed of myself for doing it).
    '''

    section = section.strip()
    tc_assert(state, section, 'Empty command section somewhere in line "{}"', line)
    return [tc_strip_quotes(a) for a in RE_ARGS.findall(section)]


def tc_strip_quotes(val):
    '''
    Strip matching single or double quotes from a token.
    '''

    # Properly quoted.
    if (val.startswith('"') and val.endswith('"')) or \
       (val.startswith("'") and val.endswith("'")):
        return val[1:-1]

    # Improperly quoted.
    assert not (val.startswith('"') or val.endswith('"') or \
                val.startswith("'") or val.endswith("'")), \
        'Mis-quoted value "{}"'.format(val)

    # Not quoted.
    return val


def tc_handle_optional(state, spec, chunks):
    '''
    Handle a trailing instance of Optional in a spec.  If the actual
    command line has one more chunk than the spec minus the Optional,
    strip it; otherwise, ignore the Optional.
    '''

    # Spec doesn't end with an Optional, so lengths must match.
    if not isinstance(spec[-1], Optional):
        tc_assert(state, len(spec) == len(chunks), 'Wrong number of sections in pipeline')
        return spec, chunks

    # Spec ends with an Optional that matches a chunk, so strip the last chunk.
    if len(spec) == len(chunks):
        return spec[:-1], chunks[:-1]

    # Spec ends with an Optional and there's one less chunk, so strip the last chunk.
    if len(spec) == (len(chunks) + 1):
        return spec[:-1], chunks

    # Pipeline length error.
    tc_assert(state, False, 'Wrong number of sections in pipeline')


def tc_check_redirect(state, redirect_out, redirect_actual):
    '''
    Check the redirection specification (if any) against the actual
    redirection in the command line.
    '''

    if redirect_out is None:
        tc_assert(state, not redirect_actual,
                  'Redirect found when none expected "{}"', redirect_actual)
    tc_match_str(state, redirect_out, redirect_actual,
                 'Redirection filename {} not matched', redirect_actual)


def tc_check_chunk(state, spec, tokens):
    '''
    Check that the tokens making up a single Unix command match a
    specification.
    '''

    assert isinstance(spec, list) and (len(spec) > 0), \
        'Non-list or empty command specification.'
    assert isinstance(tokens, list) and (len(tokens) > 0), \
        'Non-list or empty command token list.'

    cmd, optstring, filespec, constraints = tc_unpack_spec(state, spec)
    tokens = tc_check_command(state, cmd, tokens)
    optargs, filenames = tc_get_optargs_filenames(state, cmd, optstring, tokens)
    tc_check_constraints(state, cmd, constraints, optargs)
    tc_check_files(state, cmd, filespec, filenames)


def tc_get_optargs_filenames(state, cmd, optstring, tokens):
    '''
    Get the option/argument pairs and filenames, handling the case where
    no options are allowed (optstring is None).
    '''

    try:
        if optstring is None:
            optargs, filenames = getopt(tokens, '')
            tc_assert(state, not optargs,
                      'No options allowed for "{}" but some found "{}"', cmd, optargs)
        else:
            optargs, filenames = getopt(tokens, optstring)
    except GetoptError as e:
        raise AssertionError(str(e))

    return optargs, filenames


def tc_unpack_spec(state, spec):
    '''
    Unpack the specification for single command.
    '''

    assert 1 <= len(spec) <= 4, \
        'Spec must have 1-4 elements not "{}"'.format(spec)
    cmd, optstring, filespec, constraints = spec[0], None, None, None
    if len(spec) > 1: optstring = spec[1]
    if len(spec) > 2: filespec = spec[2]
    if len(spec) > 3: constraints = spec[3]
    return cmd, optstring, filespec, constraints


def tc_check_command(state, required, tokens):
    '''
    Check that the command in a chunk matches the spec.
    '''

    if isinstance(required, str):
        tc_assert(state, required == tokens[0],
                  'Expected command "{}" got "{}"', required, tokens[0])
        tokens = tokens[1:]

    elif isinstance(required, list):
        num = len(required)
        assert num > 0, \
            'Multi-part command name cannot be empty'
        tc_assert(state, required == tokens[:num],
                  'Expected command "{}" got "{}"', required, tokens[:num])
        tokens = tokens[num:]

    else:
        assert False, \
            'Command spec "{}" not handled (type "{}")'.format(required, type(required))

    return tokens


def tc_check_constraints(state, cmd, constraints, actual):
    '''
    Check that the actual values satisfy the specification constraints.
    '''

    if not constraints:
        return
    for (opt, arg) in actual:
        if opt in constraints:
            required = constraints[opt]
            tc_match_str(state, required, arg, \
                         'Command "{}" option "{}" argument "{}" not matched', cmd, opt, arg)


def tc_check_files(state, cmd, spec, actual):
    '''
    Check that actual files obey spec.
    '''

    while spec or actual:
        tc_assert(state, spec and actual,
                  'Trailing filenames for command "{}"', cmd)

        if isinstance(spec[0], set):
            num = len(spec[0])
            tc_assert(state, num <= len(actual),
                      'Command "{}" set "{}" too large for actual "{}"', cmd, spec[0], actual)
            spec_set, spec = spec[0], spec[1:]
            actual_list, actual = actual[:num], actual[num:]
            tc_assert(state, spec_set == set(actual_list),
                      'Command "{}" set "{}" does not match file list "{}"', cmd, spec_set, actual_list)

        else:
            tc_match_str(state, spec[0], actual[0], \
                         'Expected filename {} not matched', spec[0])
            spec, actual = spec[1:], actual[1:]


def tc_match_str(state, required, actual, details, *extras):
    '''
    Check that an actual string matches what's required (either a string,
    a regular expression, or a callable of one argument).
    '''

    if isinstance(required, str):
        tc_assert(state, required == actual, details, *extras)
    elif isinstance(required, RE_TYPE):
        tc_assert(state, required.match(actual), details, *extras)
    elif callable(required):
        tc_assert(state, required(actual), details, *extras)
    else:
        assert False, 'String matching spec not supported'
            


