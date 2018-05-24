import pytest
import re
from helper import prepare_state as ps
from protowhat.Test import TestFail as TF
from shellwhat_ext import \
    test_cmdline as _test_cmdline, \
    _cmdline_select_line, \
    _cmdline_parse, \
    _cmdline_get_redirect, \
    _cmdline_match_redirect, \
    _cmdline_parse_command, \
    _cmdline_strip_quotes, \
    _cmdline_match_all_commands, \
    _cmdline_match_command, \
    _cmdline_disassemble_pattern, \
    _cmdline_check_filenames, \
    _cmdline_check_constraints

def test_select_line_single_line_false():
    text = 'a'
    assert _cmdline_select_line(ps(text), False) == 'a'


def test_select_line_single_line_true():
    text = 'a'
    assert _cmdline_select_line(ps(text), True) == 'a'


def test_select_line_multi_line_false():
    text = 'a\nb\n'
    assert _cmdline_select_line(ps(text), False) == 'a\nb'


def test_select_line_multi_line_true():
    text = 'a\nb\n'
    assert _cmdline_select_line(ps(text), True) == 'b'


def test_redirect_not_found():
    text = 'a'
    _, redirect = _cmdline_get_redirect(ps(text), text)
    assert redirect is None

def test_redirect_found_with_spaces():
    text = 'a > d'
    _, redirect = _cmdline_get_redirect(ps(text), text)
    assert redirect == 'd'


def test_redirect_found_without_spaces():
    text = 'a>d'
    _, redirect = _cmdline_get_redirect(ps(text), text)
    assert redirect == 'd'


def test_redirect_double():
    text = 'a > d > e'
    with pytest.raises(TF):
        _cmdline_get_redirect(ps(text), text)


def test_redirect_before_pipe():
    text = 'a > d | e'
    with pytest.raises(TF):
        _cmdline_get_redirect(ps(text), text)


def test_redirect_dangling():
    text = 'a >'
    with pytest.raises(TF):
        _cmdline_get_redirect(ps(text), text)


def test_redirect_to_command():
    text = 'a > b c'
    with pytest.raises(TF):
        _cmdline_get_redirect(ps(text), text)


def test_redirect_cannot_open():
    text = '> b'
    with pytest.raises(TF):
        _cmdline_get_redirect(ps(text), text)


def test_parse_length_1_no_args():
    text = 'a'
    commands, _ = _cmdline_parse(ps(text), text)
    assert len(commands) == 1, 'Expected to find one command'


def test_parse_length_3_no_args():
    text = 'a | b | c'
    commands, _ = _cmdline_parse(ps(text), text)
    assert len(commands) == 3, 'Expected to find three commands'


def test_parse_length_1_with_args():
    text = 'a -b c'
    commands, _ = _cmdline_parse(ps(text), text)
    assert len(commands) == 1, 'Expected to find one command'


def test_parse_length_3_with_args():
    text = 'a -b c | d -e | f'
    commands, _ = _cmdline_parse(ps(text), text)
    assert len(commands) == 3, 'Expected to find three commands'


def test_parse_result_is_list_of_lists():
    text = 'a -b c | d -e | f'
    commands, _ = _cmdline_parse(ps(text), text)
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
    _cmdline_match_redirect(ps(), None, None)


def test_match_redirect_none_not_non_empty():
    with pytest.raises(TF):
        _cmdline_match_redirect(ps(), None, 'a')


def test_match_redirect_str_matching_str():
    _cmdline_match_redirect(ps(), 'a', 'a')


def test_match_redirect_str_mismatch_str():
    with pytest.raises(TF):
        _cmdline_match_redirect(ps(), 'a', 'b')


def test_match_redirect_re_match_str():
    _cmdline_match_redirect(ps(), re.compile(r'.+\.txt'), 'abc.txt')


def test_match_redirect_re_mismatch_str():
    with pytest.raises(TF):
        _cmdline_match_redirect(ps(), re.compile(r'.+\.txt'), 'abc.png')


def test_match_all_commands_lengths_match():
    _cmdline_match_all_commands(ps(), [['a']], [['a']])


def test_match_all_commands_lengths_mismatch():
    with pytest.raises(TF):
        _cmdline_match_all_commands(ps(), [['a']], [['a'], ['b']])


def test_match_command_pattern_is_nonempty():
    with pytest.raises(AssertionError):
        _cmdline_match_command(ps(), [], ['a'])

def test_match_command_actual_is_nonempty():
    with pytest.raises(AssertionError):
        _cmdline_match_command(ps(), ['a'], [])

def test_match_command_commands_match():
    _cmdline_match_command(ps(), ['a'], ['a'])


def test_match_command_commands_mismatch():
    with pytest.raises(TF):
        _cmdline_match_command(ps(), ['a'], ['b'])


def test_match_command_unexpected_actual_parameters():
    with pytest.raises(TF):
        _cmdline_match_command(ps(), ['a'], ['b', 'c'])


def test_match_command_no_flags_and_non_provided():
    _cmdline_match_command(ps(), ['a', ''], ['a'])


def test_match_command_no_flags_and_some_provided():
    with pytest.raises(TF):
        _cmdline_match_command(ps(), ['a', ''], ['a', '-b'])


def test_match_command_no_flags_and_filenames_provided():
    with pytest.raises(TF):
        _cmdline_match_command(ps(), ['a', ''], ['a', 'filename'])


def test_match_command_single_flag_no_argument_match():
    _cmdline_match_command(ps(), ['a', 'b'], ['a', '-b'])


def test_match_command_single_flag_no_argument_mismatch():
    with pytest.raises(TF):
        _cmdline_match_command(ps(), ['a', 'b'], ['a', '-X'])


def test_match_command_trailing_files_not_expected():
    with pytest.raises(TF):
        _cmdline_match_command(ps(), ['a', 'b'], ['a', '-b', 'filename'])


def test_match_command_trailing_files_star_allowed_none_provided():
    _cmdline_match_command(ps(), ['a', 'b', '*'], ['a', '-b'])


def test_match_command_trailing_files_star_allowed_two_provided():
    _cmdline_match_command(ps(), ['a', 'b', '*'], ['a', '-b', 'file1', 'file2'])


def test_match_command_trailing_files_plus_allowed_none_provided():
    with pytest.raises(TF):
        _cmdline_match_command(ps(), ['a', 'b', '+'], ['a', '-b'])


def test_match_command_filename_list_match():
    _cmdline_match_command(ps(), ['a', '', ['first.txt', 'second.txt']], ['a', 'first.txt', 'second.txt'])


def test_match_command_filename_list_wrong_order():
    with pytest.raises(TF):
        _cmdline_match_command(ps(), ['a', '', ['first.txt', 'second.txt']], ['a', 'second.txt', 'first.txt'])


def test_match_command_filename_list_too_short():
    with pytest.raises(TF):
        _cmdline_match_command(ps(), ['a', '', ['first.txt']], ['a', 'second.txt', 'first.txt'])


def test_match_command_filename_list_too_long():
    with pytest.raises(TF):
        _cmdline_match_command(ps(), ['a', '', ['first.txt', 'second.txt']], ['a', 'first.txt'])


def test_match_command_filename_list_wrong_names():
    with pytest.raises(TF):
        _cmdline_match_command(ps(), ['a', '', ['first.txt', 'second.txt']], ['a', 'first.txt', 'third.txt'])


def test_match_command_filename_re_match_simple():
    _cmdline_match_command(ps(), ['a', '', [re.compile(r'first\.txt')]], ['a', 'first.txt'])


def test_match_command_filename_re_match_pattern():
    _cmdline_match_command(ps(), ['a', '', [re.compile(r'.+\.txt')]], ['a', 'first.txt'])


def test_match_command_filename_re_match_trailing():
    _cmdline_match_command(ps(), ['cp', '', ['first.txt', re.compile(r'dir/?')]], ['cp', 'first.txt', 'dir/'])


def test_match_command_filename_set_match_in_order():
    _cmdline_match_command(ps(), ['a', '', {'first.txt', 'second.txt'}], ['a', 'first.txt', 'second.txt'])


def test_match_command_filename_set_match_wrong_order():
    _cmdline_match_command(ps(), ['a', '', {'first.txt', 'second.txt'}], ['a', 'second.txt', 'first.txt'])


def test_match_command_filename_set_too_short():
    with pytest.raises(TF):
        _cmdline_match_command(ps(), ['a', '', {'first.txt'}], ['a', 'second.txt', 'first.txt'])


def test_match_command_filename_set_too_long():
    with pytest.raises(TF):
        _cmdline_match_command(ps(), ['a', '', {'first.txt', 'second.txt'}], ['a', 'first.txt'])


def test_match_command_filename_set_wrong_names():
    with pytest.raises(TF):
        _cmdline_match_command(ps(), ['a', '', {'first.txt', 'second.txt'}], ['a', 'first.txt', 'third.txt'])


def test_constraint_text_match():
    _cmdline_match_command(ps(), ['a', 'n:', None, {'-n' : '3'}], ['a', '-n', '3'])


def test_constraint_text_mismatch():
    with pytest.raises(TF):
        _cmdline_match_command(ps(), ['a', 'n:', None, {'-n' : '3'}], ['a', '-n', 'X'])


def test_constraint_regexp_match():
    _cmdline_match_command(ps(), ['a', 'n:', None, {'-n' : re.compile(r'^aaa$')}], ['a', '-n', 'aaa'])


def test_constraint_regexp_mismatch():
    with pytest.raises(TF):
        _cmdline_match_command(ps(), ['a', 'n:', None, {'-n' : re.compile(r'^aaa$')}], ['a', '-n', 'bbb'])


def test_constraint_callable_match():
    _cmdline_match_command(ps(), ['a', 'n:', None, {'-n' : lambda x: len(x) == 1}], ['a', '-n', 'X'])


def test_constraint_callable_mismatch():
    with pytest.raises(TF):
        _cmdline_match_command(ps(), ['a', 'n:', None, {'-n' : lambda x: len(x) == 1}], ['a', '-n', 'XYZ'])


def test_overall_command_only_match():
    _test_cmdline(ps('a'), [['a']])


def test_overall_command_only_mismatch():
    with pytest.raises(TF):
        _test_cmdline(ps('a'), [['b']])


def test_overall_pipeline():
    actual = 'wc -l a.txt b.txt "c.txt d.txt" | sort -n -r | head -n 3 > result.txt'
    pattern = [['wc',   'l', '+'],
	       ['sort', 'nr'],
	       ['head', 'n:', None, {'-n' : '3'}]]
    _test_cmdline(ps(actual), pattern, redirect=re.compile(r'.+\.txt'), msg='Incorrect command line')


def test_debug_match_command():
    pattern = [['abc',   'l']]
    actual = 'wc -l'
    with pytest.raises(TF):
        _test_cmdline(ps(actual), pattern, debug='EXTRA MESSAGE')
