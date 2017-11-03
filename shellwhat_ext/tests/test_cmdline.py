import pytest
from getopt import getopt
import re


PAT_TYPE = type(re.compile('x'))
PAT_ARGS = re.compile('{}|{}|{}'.format(r'[^"\'\s]+', r"'[^']+'", r'"[^"]+"'))


class State(object):
    def __init__(self, student_result=''):
        self.student_result = student_result

    def do_test(self, msg):
        raise Exception(msg)


def test_redirect_not_found():
    _, redirect = _cmdline_get_redirect(State('a'))
    assert redirect is None


def test_redirect_found_with_spaces():
    _, redirect = _cmdline_get_redirect(State('a > d'))
    assert redirect == 'd'


def test_redirect_found_without_spaces():
    _, redirect = _cmdline_get_redirect(State('a>d'))
    assert redirect == 'd'


def test_redirect_double():
    with pytest.raises(Exception):
        _cmdline_get_redirect(State('a > d > e'))


def test_redirect_before_pipe():
    with pytest.raises(Exception):
        _cmdline_get_redirect(State('a > d | e'))


def test_redirect_dangling():
    with pytest.raises(Exception):
        _cmdline_get_redirect(State('a >'))


def test_redirect_to_command():
    with pytest.raises(Exception):
        _cmdline_get_redirect(State('a > b c'))


def test_redirect_cannot_open():
    with pytest.raises(Exception):
        _cmdline_get_redirect(State('> b'))


def test_parse_length_1_no_args():
    commands, _ = _cmdline_parse(State('a'))
    assert len(commands) == 1, 'Expected to find one command'


def test_parse_length_3_no_args():
    commands, _ = _cmdline_parse(State('a | b | c'))
    assert len(commands) == 3, 'Expected to find three commands'


def test_parse_length_1_with_args():
    commands, _ = _cmdline_parse(State('a -b c'))
    assert len(commands) == 1, 'Expected to find one command'


def test_parse_length_3_with_args():
    commands, _ = _cmdline_parse(State('a -b c | d -e | f'))
    assert len(commands) == 3, 'Expected to find three commands'


def test_parse_result_is_list_of_lists():
    commands, _ = _cmdline_parse(State('a -b c | d -e | f'))
    assert all([type(c) == list for c in commands]), 'Expected all parsed elements to be lists'


def test_parse_command_only():
    assert _cmdline_parse_command('a') == ['a'], 'Expected command at start of chunk'


def test_parse_command_with_flag_only():
    assert _cmdline_parse_command('a -b') == ['a', '-b'], 'Expected command and flag'


def test_parse_command_with_flag_and_argument():
    assert _cmdline_parse_command('a -b c') == ['a', '-b', 'c'], 'Expected command, flag, and argument'


def test_parse_command_with_single_quoted_argument():
    assert _cmdline_parse_command("a -b 'single quoted' -c") == ['a', '-b', 'single quoted', '-c']


def test_parse_command_with_double_quoted_argument():
    assert _cmdline_parse_command('a -b "double quoted"') == ['a', '-b', 'double quoted']


def test_match_redirect_none_with_empty():
    _cmdline_match_redirect(State(), None, None)


def test_match_redirect_none_not_non_empty():
    with pytest.raises(Exception):
        _cmdline_match_redirect(State(), None, 'a')


def test_match_redirect_str_matching_str():
    _cmdline_match_redirect(State(), 'a', 'a')


def test_match_redirect_str_mismatch_str():
    with pytest.raises(Exception):
        _cmdline_match_redirect(State(), 'a', 'b')


def test_match_redirect_re_match_str():
    _cmdline_match_redirect(State(), re.compile(r'.+\.txt'), 'abc.txt')


def test_match_redirect_re_mismatch_str():
    with pytest.raises(Exception):
        _cmdline_match_redirect(State(), re.compile(r'.+\.txt'), 'abc.png')


def test_match_all_commands_lengths_match():
    _cmdline_match_all_commands(State(), [['a']], [['a']])


def test_match_all_commands_lengths_mismatch():
    with pytest.raises(Exception):
        _cmdline_match_all_commands(State(), [['a']], [['a'], ['b']])


def test_match_command_pattern_is_nonempty():
    with pytest.raises(Exception):
        _cmdline_match_command(State(), [], ['a'])


def test_match_command_actual_is_nonempty():
    with pytest.raises(Exception):
        _cmdline_match_command(State(), ['a'], [''])


def test_match_command_commands_match():
    _cmdline_match_command(State(), ['a'], ['a'])


def test_match_command_commands_mismatch():
    with pytest.raises(Exception):
        _cmdline_match_command(State(), ['a'], ['b'])


def test_match_command_unexpected_actual_parameters():
    with pytest.raises(Exception):
        _cmdline_match_command(State(), ['a'], ['b', 'c'])


def test_match_command_no_flags_and_non_provided():
    _cmdline_match_command(State(), ['a', ''], ['a'])


def test_match_command_no_flags_and_some_provided():
    with pytest.raises(Exception):
        _cmdline_match_command(State(), ['a', ''], ['a', '-b'])


def test_match_command_no_flags_and_filenames_provided():
    with pytest.raises(Exception):
        _cmdline_match_command(State(), ['a', ''], ['a', 'filename'])


def test_match_command_single_flag_no_argument_match():
    _cmdline_match_command(State(), ['a', 'b'], ['a', '-b'])


def test_match_command_single_flag_no_argument_mismatch():
    with pytest.raises(Exception):
        _cmdline_match_command(State(), ['a', 'b'], ['a', '-X'])


def test_match_command_trailing_files_not_expected():
    with pytest.raises(Exception):
        _cmdline_match_command(State(), ['a', 'b'], ['a', '-b', 'filename'])


def test_match_command_trailing_files_star_allowed_none_provided():
    _cmdline_match_command(State(), ['a', 'b', '*'], ['a', '-b'])


def test_match_command_trailing_files_star_allowed_two_provided():
    _cmdline_match_command(State(), ['a', 'b', '*'], ['a', '-b', 'file1', 'file2'])


def test_match_command_trailing_files_plus_allowed_none_provided():
    with pytest.raises(Exception):
        _cmdline_match_command(State(), ['a', 'b', '+'], ['a', '-b'])


def test_constraint_text_match():
    _cmdline_match_command(State(), ['a', 'n:', None, {'-n' : '3'}], ['a', '-n', '3'])


def test_constraint_text_mismatch():
    with pytest.raises(Exception):
        _cmdline_match_command(State(), ['a', 'n:', None, {'-n' : '3'}], ['a', '-n', 'X'])


def test_constraint_regexp_match():
    _cmdline_match_command(State(), ['a', 'n:', None, {'-n' : re.compile(r'^aaa$')}], ['a', '-n', 'aaa'])


def test_constraint_regexp_mismatch():
    with pytest.raises(Exception):
        _cmdline_match_command(State(), ['a', 'n:', None, {'-n' : re.compile(r'^aaa$')}], ['a', '-n', 'bbb'])


def test_constraint_callable_match():
    _cmdline_match_command(State(), ['a', 'n:', None, {'-n' : lambda x: len(x) == 1}], ['a', '-n', 'X'])


def test_constraint_callable_mismatch():
    with pytest.raises(Exception):
        _cmdline_match_command(State(), ['a', 'n:', None, {'-n' : lambda x: len(x) == 1}], ['a', '-n', 'XYZ'])


def test_overall_command_only_match():
    t_cmdline(State('a'), [['a']])


def test_overall_command_only_mismatch():
    with pytest.raises(Exception):
        t_cmdline(State('a'), [['b']])


def test_overall_pipeline():
    actual = 'wc -l a.txt b.txt "c.txt d.txt" | sort -n -r | head -n 3 > result.txt'
    pattern = [['wc',   'l', '+'],
	       ['sort', 'nr'],
	       ['head', 'n:', None, {'-n' : '3'}]]
    t_cmdline(State(actual), pattern, redirect=re.compile(r'.+\.txt'), msg='Incorrect command line')
             

#-------------------------------------------------------------------------------


def t_cmdline(state, pattern, redirect=None, msg='Error'):
    actualCommands, actualRedirect = _cmdline_parse(state)
    _cmdline_match_redirect(state, redirect, actualRedirect)
    _cmdline_match_all_commands(state, pattern, actualCommands)
    return state


def _cmdline_parse(state):
    stripped, redirect = _cmdline_get_redirect(state)
    commands = [_cmdline_parse_command(c.strip()) for c in stripped.strip().split('|')]
    return commands, redirect


def _cmdline_get_redirect(state):

    text = state.student_result

    if '>' not in text:
        return text, None
    if text.count('>') > 1:
        state.do_test('Command line can contain at most one ">"')

    pre, post = [x.strip() for x in text.split('>')]

    if not pre:
        state.do_test('Line cannot start with redirection')
    if not post:
        state.do_test('Dangling ">" at end of line')
    if '|' in post:
        state.do_test('Cannot redirect to something containing a pipe "{}".format(post)')
    if ' ' in post:
        state.do_test('Cannot redirect to something containin spaces "{}"'.format(post))

    return pre, post


def _cmdline_match_redirect(state, pattern, actual):
    if pattern is None:
        if actual:
            state.do_test('Redirect found when none expected "{}"'.format(actual))
    elif isinstance(pattern, str):
        if pattern != actual:
            state.do_test('Pattern "{}" does not match actual "{}"'.format(pattern, actual))
    elif type(pattern) == PAT_TYPE:
        if not pattern.search(actual):
            state.do_test('Regular expression "{}" does not match actual "{}"'.format(pattern.pattern, actual))


def _cmdline_parse_command(text):
    return [_cmdline_strip_quotes(a) for a in PAT_ARGS.findall(text)]


def _cmdline_strip_quotes(val):
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        val = val[1:-1]
    return val


def _cmdline_match_all_commands(state, pattern, actual):
    if len(pattern) != len(actual):
        state.do_test('Unexpected number of components in command line: expected "{}" found "{}"'.format(len(pattern), len(actual)))
    for (p, a) in zip(pattern, actual):
        _cmdline_match_command(state, p, a)


def _cmdline_match_command(state, pattern, actual):

    # Command.
    assert len(pattern) > 0, 'Pattern must have at least a command name'
    assert len(actual) > 0, 'Command cannot be empty'

    # Disassemble pattern.
    pat_cmd, pat_optstring, pat_filespec, pat_constraints = _cmdline_disassemble_pattern(pattern)
    if pat_cmd != actual[0]:
        state.do_test('Expected command "{}" got "{}"'.format(pat_cmd, actual[0]))

    # No parameters allowed.
    if pat_optstring is None:
        if len(actual) > 1:
            state.do_test('Pattern does not allow parameters but actual command contains some "{}"'.format(actual))
        return state

    # Get actual flags, their arguments, and trailing filenames.
    actual_opts, actual_extras = getopt(actual[1:], pat_optstring)

    # Check trailing filenames both ways.
    _cmdline_check_filenames(state, pat_cmd, pat_filespec, actual_extras)

    # Check constraints.
    _cmdline_check_constraints(state, pat_cmd, pat_constraints, actual_opts)


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


def _cmdline_check_filenames(state, cmd, filespec, extras):
    if filespec is None:
        if extras:
            state.do_test('Unexpected trailing filenames "{}" for "{}"'.format(extras, cmd))
    elif isinstance(filespec, str):
        if filespec == '*':
            pass
        elif filespec == '+':
            if len(extras) == 0:
                state.do_test('Expected one or more trailing filenames, got none for "{}"'.format(cmd))
        else:
            assert False, 'Unrecognized string for pattern file spec "{}"'.format(filespec)
    else:
        assert False, 'Non-string pattern filespec not yet implemented "{}"'.format(filespec) # FIXME


def _cmdline_check_constraints(state, cmd, constraints, opts):
    if constraints is None:
        return
    for (opt, arg) in opts:
        if opt in constraints:
            required = constraints[opt]
            if callable(required):
                if not required(arg):
                    state.do_test('Argument "{}" of flag "{}" for "{}" failed test'.format(arg, opt, cmd))
            elif type(required) == PAT_TYPE:
                if not required.search(arg):
                    state.do_test('Argument "{}" of flag "{}" for "{}" does not match pattern "{}"'.format(arg, opt, cmd, required.pattern))
            else:
                if arg != required:
                    state.do_test('Argument "{}" of flag "{}" for "{}" does not match required "{}"'.format(arg, opt, cmd, required))
