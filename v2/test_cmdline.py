'''Test command line without fully parsing.

`test_cmdline` tests a Unix command line containing pipes and output
redirection against a specification.  An example of its use is:

    test_cmdline(state,
                 [['extract', '', [rxc(r'p.+\.txt'), {'data/b.csv', 'data/a.csv'}]],
                  ['sort', 'n'],
                  ['tail', 'n:', [], {'-n' : '3'}]],
                 'Use extract, sort, and tail with redirection.',
                 redirect_out=re.compile(r'.+\.csv'),
                 last_line_only=True)

which will correctly match the command line:

    '\n\nextract params.txt data/a.csv data/b.csv | sort -n | tail -n 3 > last.csv\n'

The required parameters to `test_cmdline` are:

-   The SCT state object.  If the function is called using `Ex() >>
    test_cmdline(...)`, this parameter does not have to be supplied.

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

import pytest
import re
from getopt import getopt, GetoptError


rxc = re.compile
RE_TYPE = type(rxc(''))
RE_ARGS = re.compile('{}|{}|{}'.format(r'[^"\'\s]+', r"'[^']+'", r'"[^"]+"'))


class Optional(object):
    '''
    Marker class for optional last command in a pipeline.
    '''

    def __init__(self, text='unspecified'):
        self.text = text


@pytest.mark.skip(reason='This is not a unit testing function.')
def test_cmdline(state, spec, msg, redirect_out=None, last_line_only=False, debug=False):
    '''
    Check that a complicated command line matches a spec.
    '''

    assert spec, \
        'Empty spec for "{}"'.format(text)

    state.tc_debug = state.tc_debug or debug
    state.tc_msg = msg

    tc_assert(state, state.student_code, 'No student code provided')

    chunks, redirect_actual = tc_parse_cmdline(state, last_line_only)
    tc_check_redirect(state, redirect_out, redirect_actual)
    spec, chunks = tc_handle_optional(state, spec, chunks)
    for (s, c) in zip(spec, chunks):
        tc_check_chunk(state, s, c)


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
        tc_assert(state, not actual,
                  'Redirect found when none expected "{}"', actual)
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
        assert False, 'String matching spec "{}" not supported'.format(spec)
            

def tc_assert(state, condition, details, *extras):
    '''
    Fail if condition not true. Always report msg; report details if debug
    set in state.
    '''

    if condition:
        return
    if hasattr(state, 'tc_debug') and state.tc_debug:
        state.tc_msg = state.tc_msg + ':: ' + details.format(*extras)
    state.do_test(state.tc_msg)


#-------------------------------------------------------------------------------
# Placeholder State object for testing purposes.


class State(object):
    def __init__(self, student_code='', msg='MAIN ERROR MESSAGE'):
        self.student_code = student_code
        self.tc_debug = True
        self.tc_msg = ''

    def do_test(self, msg):
        raise Exception(msg)


#-------------------------------------------------------------------------------
# Our own assertion function.


def test_assert_passes():
    tc_assert(State(), True, 'failing when it should not')


def test_assert_fails_when_it_should():
    with pytest.raises(Exception):
        tc_assert(State(), False, 'not failing when it should')


#-------------------------------------------------------------------------------
# Matching strings against strings, regex, and callables.


def test_match_str_equal_strings():
    tc_match_str(State(), 'abc', 'abc', 'equal strings fail to match')


def test_match_str_unequal_strings():
    with pytest.raises(Exception):
        tc_match_str(State(), 'abc', 'def', 'unequal strings match')


def test_match_str_regex_match():
    tc_match_str(State(), rxc(r'ab+c'), 'abbbc', 'regex fails to match')


def test_match_str_regex_mismatch():
    with pytest.raises(Exception):
        tc_match_str(State(), rxc(r'ab+c'), 'ac', 'regex matches incorrectly')


def test_match_str_callable_match():
    tc_match_str(State(), lambda x: x > 0, 123, 'callable fails to match')


def test_match_str_callable_mismatch():
    with pytest.raises(Exception):
        tc_match_str(State(), lambda x: x > 0, -999, 'callable matches incorrectly')


#-------------------------------------------------------------------------------
# Checking lists of files against file specs.


def test_files_empty_empty_passes():
    tc_check_files(State(), 'CMD', [], [])


def test_files_empty_nonempty_fails():
    with pytest.raises(Exception):
        tc_check_files(State(), 'CMD', [], ['whoops'])


def test_files_nonempty_empty_fails():
    with pytest.raises(Exception):
        tc_check_files(State(), 'CMD', ['whoops'], [])


def test_files_text_match_succeeds():
    tc_check_files(State(), 'CMD', ['a'], ['a'])


def test_files_text_mismatch_fails():
    with pytest.raises(Exception):
        tc_check_files(State(), 'CMD', ['a'], ['b'])


def test_files_text_lengthy_match_succeeds():
    tc_check_files(State(), 'CMD', ['a', 'b'], ['a', 'b'])


def test_files_text_lengthy_mismatch_fails():
    with pytest.raises(Exception):
        tc_check_files(State(), 'CMD', ['b', 'a'], ['a', 'b'])


def test_files_text_overlong_expected_fails():
    with pytest.raises(Exception):
        tc_check_files(State(), 'CMD', ['a', 'b', 'c'], ['a', 'b'])


def test_files_text_overlong_actual_fails():
    with pytest.raises(Exception):
        tc_check_files(State(), 'CMD', ['a', 'b'], ['a', 'b', 'c'])


def test_files_regex_match_succeeds():
    tc_check_files(State(), 'CMD', [rxc(r'ab+c')], ['abbbc'])


def test_files_regex_mismatch_fails():
    with pytest.raises(Exception):
        tc_check_files(State(), 'CMD', [rxc(r'ab+c')], ['b'])


def test_files_regex_trailing_match_succeeds():
    tc_check_files(State(), 'CMD', ['x', rxc(r'ab+c')], ['x', 'abbbc'])


def test_files_regex_trailing_mismatch_fails():
    with pytest.raises(Exception):
        tc_check_files(State(), 'CMD', ['x', rxc(r'ab+c')], ['y', 'b'])


def test_files_callable_match_succeeds():
    tc_check_files(State(), 'CMD', [lambda x: len(x) == 5], ['abbbc'])


def test_files_callable_mismatch_fails():
    with pytest.raises(Exception):
        tc_check_files(State(), 'CMD', [lambda x: len(x) == 5], ['b'])


def test_files_callable_trailing_match_succeeds():
    tc_check_files(State(), 'CMD', ['x', lambda x: len(x) == 5], ['x', 'abbbc'])


def test_files_callable_trailing_mismatch_fails():
    with pytest.raises(Exception):
        tc_check_files(State(), 'CMD', ['x', lambda x: len(x) == 5], ['y', 'b'])


def test_files_singleton_set_match():
    tc_check_files(State(), 'CMD', [{'x'}], ['x'])


def test_files_singleton_set_mismatch():
    with pytest.raises(Exception):
        tc_check_files(State(), 'CMD', [{'x'}], ['y'])


def test_files_double_set_match():
    tc_check_files(State(), 'CMD', [{'x', 'y'}], ['x', 'y'])


def test_files_double_set_mismatch():
    with pytest.raises(Exception):
        tc_check_files(State(), 'CMD', [{'x', 'y'}], ['a', 'y'])


def test_files_set_with_leading_match():
    tc_check_files(State(), 'CMD', ['a', {'x', 'y'}], ['a', 'x', 'y'])


def test_files_set_with_leading_mismatch():
    with pytest.raises(Exception):
        tc_check_files(State(), 'CMD', ['a', {'x', 'y'}], ['b', 'x', 'y'])


def test_files_set_with_trailing_match():
    tc_check_files(State(), 'CMD', [{'x', 'y'}, 'a'], ['x', 'y', 'a'])


def test_files_set_with_trailing_mismatch():
    with pytest.raises(Exception):
        tc_check_files(State(), 'CMD', [{'x', 'y'}, 'a'], ['x', 'y', 'b'])


def test_files_set_with_leading_as_trailing_mismatch():
    with pytest.raises(Exception):
        tc_check_files(State(), 'CMD', ['a', {'x', 'y'}], ['x', 'y', 'a'])


#-------------------------------------------------------------------------------
# Checking actual command-line arguments against specs.


def test_constraints_empty_empty_passes():
    tc_check_constraints(State(), 'CMD', {}, [])


def test_constraints_str_empty_nonempty_passes():
    tc_check_constraints(State(), 'CMD', {}, [('-a', '1')])


def test_constraints_str_nonempty_empty_passes():
    tc_check_constraints(State(), 'CMD', {'-a' : '1'}, [])


def test_constraints_str_single_match():
    tc_check_constraints(State(), 'CMD', {'-a' : '1'}, [('-a', '1')])


def test_constraints_str_single_mismatch_option():
    tc_check_constraints(State(), 'CMD', {'-a' : '1'}, [('-b', '1')])


def test_constraints_str_single_mismatch_arg():
    with pytest.raises(Exception):
        tc_check_constraints(State(), 'CMD', {'-a' : '1'}, [('-a', '999')])


def test_constraints_str_repeated_actual_match():
    tc_check_constraints(State(), 'CMD', {'-a' : '1'}, [('-a', '1'), ('-a', '1')])


def test_constraints_str_repeated_actual_mismatch():
    with pytest.raises(Exception):
        tc_check_constraints(State(), 'CMD', {'-a' : '1'}, [('-a', '1'), ('-a', '999')])


def test_constraints_str_multiple_match():
    tc_check_constraints(State(), 'CMD', {'-a' : '1', '-b' : '2'}, [('-a', '1'), ('-b', '2')])


def test_constraints_str_multiple_one_mismatch():
    with pytest.raises(Exception):
        tc_check_constraints(State(), 'CMD', {'-a' : '1', '-b' : '2'}, [('-a', '1'), ('-b', '999')])


def test_constraints_str_regex_match():
    tc_check_constraints(State(), 'CMD', {'-a' : rxc(r'ab+c')}, [('-a', 'abbbc')])


def test_constraints_str_regex_mismatch():
    with pytest.raises(Exception):
        tc_check_constraints(State(), 'CMD', {'-a' : rxc(r'ab+c')}, [('-a', 'b')])


def test_constraints_everything_match():
    tc_check_constraints(State(), 'CMD',
                         {'-a' : '1', '-b' : rxc(r'ab+c'), '-c' : lambda x: int(x) > 5, '-d' : 'xyz'},
                         [('-c', '99'), ('-b', 'abbbc'), ('-e', 'not checked')])


#-------------------------------------------------------------------------------
# Checking command names.


def test_command_name_match():
    remainder = tc_check_command(State(), 'a', ['a'])
    assert remainder == [], 'Wrong remainder'


def test_command_name_mismatch():
    with pytest.raises(Exception):
        tc_check_command(State(), 'a', ['b'])


def test_command_multi_empty_fails():
    with pytest.raises(Exception):
        tc_check_command(State(), [], ['a', '-b'])


def test_command_multi_match():
    remainder = tc_check_command(State(), ['a', 'b'], ['a', 'b'])
    assert remainder == [], 'Wrong remainder'


def test_command_multi_mismatch():
    with pytest.raises(Exception):
        tc_check_command(State(), ['a', 'c'], ['a', 'b'])


def test_command_remainder_single():
    remainder = tc_check_command(State(), 'a', ['a', 'b'])
    assert remainder == ['b'], 'Wrong remainder'


def test_command_remainder_multi():
    remainder = tc_check_command(State(), ['a', 'b'], ['a', 'b', 'c', 'd'])
    assert remainder == ['c', 'd'], 'Wrong remainder'


#-------------------------------------------------------------------------------
# Checking a single chunk.


def test_chunk_command_name_only_match():
    tc_check_chunk(State(),
                   ['a'],
                   'a'.split())


def test_chunk_command_name_only_mismatch():
    with pytest.raises(Exception):
        tc_check_chunk(State(),
                       ['a'],
                       'b'.split())


def test_chunk_no_options_allowed_match():
    tc_check_chunk(State(),
                   ['a', None],
                   'a'.split())


def test_chunk_no_options_allowed_mismatch():
    with pytest.raises(Exception):
        tc_check_chunk(State(),
                       ['a', None],
                       'a -b'.split())


def test_chunk_bare_option_match():
    tc_check_chunk(State(),
                   ['a', 'b'],
                   'a -b'.split())


def test_chunk_bare_option_mismatch():
    with pytest.raises(Exception):
        tc_check_chunk(State(),
                       ['a', 'b'],
                       'a -c'.split())


def test_chunk_bare_option_allowed():
    tc_check_chunk(State(),
                   ['a', 'bc'],
                   'a -c'.split())


def test_chunk_arg_option_match():
    tc_check_chunk(State(),
                   ['a', 'b:'],
                   'a -b xyz'.split())


def test_chunk_arg_option_value_match():
    tc_check_chunk(State(),
                   ['a', 'b:', [], {'-b' : 'xyz'}],
                   'a -b xyz'.split())


def test_chunk_arg_option_value_mismatch():
    with pytest.raises(Exception):
        tc_check_chunk(State(),
                       ['a', 'b:', [], {'-b' : 'xyz'}],
                       'a -b pqr'.split())


def test_chunk_arg_option_value_pattern_match():
    tc_check_chunk(State(),
                   ['a', 'b:', [], {'-b' : rxc(r'ab+c')}],
                   'a -b abbbc'.split())


def test_chunk_arg_option_value_pattern_mismatch():
    with pytest.raises(Exception):
        tc_check_chunk(State(),
                       ['a', 'b:', [], {'-b' : rxc(r'ab+c')}],
                       'a -b x'.split())


def test_chunk_filename_match():
    tc_check_chunk(State(),
                   ['a', '', ['x']],
                   'a x'.split())


def test_chunk_filename_mismatch():
    with pytest.raises(Exception):
        tc_check_chunk(State(),
                       ['a', '', ['x']],
                       'a y'.split())


def test_chunk_multi_filename_match():
    tc_check_chunk(State(),
                   ['a', '', ['x', 'y', rxc(r'zz+')]],
                   'a x y zzzzzzz'.split())


def test_chunk_multi_filename_mismatch():
    with pytest.raises(Exception):
        tc_check_chunk(State(),
                       ['a', '', ['x', 'y', rxc(r'zz+')]],
                       'a x y zqqz'.split())


def test_chunk_args_and_filenames_match():
    tc_check_chunk(State(),
                   [['a', 'b'], 'c:d', ['p', {'q', 'r'}, 's'], {'-c' : 'NNN'}],
                   'a b -c NNN -d p r q s'.split())


def test_chunk_args_and_filenames_arg_mismatch():
    with pytest.raises(Exception):
        tc_check_chunk(State(),
                       [['a', 'b'], 'cd:', ['p', {'q', 'r'}, 's'], {'-c' : 'NNN'}],
                       'a b -c NNN -d p r q s'.split())


def test_chunk_args_and_filenames_filename_mismatch():
    with pytest.raises(Exception):
        tc_check_chunk(State(),
                       [['a', 'b'], 'c:d', ['p', 'q', 'r', 's'], {'-c' : 'NNN'}],
                       'a b -c NNN -d p r q s'.split())


#-------------------------------------------------------------------------------
# Check that optional pipeline elements are handled correctly.


def test_optional_absent_unneeded():
    assert tc_handle_optional(State(), [['a']], [['a']]) == ([['a']], [['a']])


def test_optional_absent_needed():
    with pytest.raises(Exception):
        assert tc_handle_optional(State(), [['a']], [['a'], ['b']])


def test_optional_present_unneeded():
    assert tc_handle_optional(State(), [['a'], Optional()], [['a']]) == ([['a']], [['a']])


def test_optional_present_needed():
    assert tc_handle_optional(State(), [['a'], Optional()], [['a'], ['b']])


def test_optional_present_still_too_short():
    with pytest.raises(Exception):
        assert tc_handle_optional(State(), [['a'], Optional()], [['a'], ['b'], ['c']])


#-------------------------------------------------------------------------------
# Checking command-line parsing.


def test_parse_cmdline_single_bare_command():
    assert tc_parse_cmdline(State('a')) == ([['a']], None)


def test_parse_cmdline_double_bare_commands():
    assert tc_parse_cmdline(State('a | b')) == ([['a'], ['b']], None)


def test_parse_cmdline_single_command_with_args():
    assert tc_parse_cmdline(State('a -b')) == ([['a', '-b']], None)


def test_parse_cmdline_single_command_with_redirect():
    assert tc_parse_cmdline(State('a > b')) == ([['a']], 'b')


def test_parse_cmdline_pipe_with_redirect():
    assert tc_parse_cmdline(State('a|b -c -d  "eee"  | f g  -h > z')) \
        == \
        ([['a'], ['b', '-c', '-d', 'eee'], ['f', 'g', '-h']], 'z')


def test_parse_cmdline_leading_redirect():
    with pytest.raises(Exception):
        tc_parse_cmdline(State('> b'))


def test_parse_cmdline_trailing_redirect():
    with pytest.raises(Exception):
        tc_parse_cmdline(State('b >'))


def test_parse_cmdline_pipe_after_redirect():
    with pytest.raises(Exception):
        tc_parse_cmdline(State('b > c | d'))


def test_parse_cmdline_multiple_redirect():
    with pytest.raises(Exception):
        tc_parse_cmdline(State('b > c > d'))


def test_parse_cmdline_last_line_flag_not_set():
    with pytest.raises(Exception):
        assert tc_parse_cmdline(State('a\nb'))


def test_parse_cmdline_last_line_flag_set():
    assert tc_parse_cmdline(State('a\nb'), last_line_only=True) == ([['b']], None)


#-------------------------------------------------------------------------------
# Test the whole thing.


def test_cmdline_example():
    test_cmdline(State('\n# a comment\nextract params.txt data/b.csv data/a.csv | sort -n | tail -n 3 > last.csv\n'),
                 [['extract', '', [rxc(r'p.+\.txt'), {'data/a.csv', 'data/b.csv'}]],
                  ['sort', 'n'],
                  ['tail', 'n:', [], {'-n' : '3'}]],
                 'Use extract, sort, and tail with redirection.',
                 redirect_out=re.compile(r'.+\.csv'),
                 last_line_only=True)
