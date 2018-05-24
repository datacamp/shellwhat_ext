import pytest
import re
from helper import prepare_state as ps
from protowhat.Test import TestFail as TF
from shellwhat_ext import \
    test_cmdline_v2 as _test_cmdline, \
    Optional, \
    tc_parse_cmdline, \
    tc_get_redirect, \
    tc_parse_chunk, \
    tc_strip_quotes, \
    tc_handle_optional, \
    tc_check_redirect, \
    tc_check_chunk, \
    tc_get_optargs_filenames, \
    tc_unpack_spec, \
    tc_check_command, \
    tc_check_constraints, \
    tc_check_files, \
    tc_match_str, \
    tc_assert
rxc = re.compile

#-------------------------------------------------------------------------------
# Our own assertion function.


def test_assert_passes():
    tc_assert(ps(), True, 'failing when it should not')


def test_assert_fails_when_it_should():
    with pytest.raises(TF):
        tc_assert(ps(), False, 'not failing when it should')

#-------------------------------------------------------------------------------
# Matching strings against strings, regex, and callables.


def test_match_str_equal_strings():
    tc_match_str(ps(), 'abc', 'abc', 'equal strings fail to match')


def test_match_str_unequal_strings():
    with pytest.raises(TF):
        tc_match_str(ps(), 'abc', 'def', 'unequal strings match')


def test_match_str_regex_match():
    tc_match_str(ps(), rxc(r'ab+c'), 'abbbc', 'regex fails to match')


def test_match_str_regex_mismatch():
    with pytest.raises(TF):
        tc_match_str(ps(), rxc(r'ab+c'), 'ac', 'regex matches incorrectly')


def test_match_str_callable_match():
    tc_match_str(ps(), lambda x: x > 0, 123, 'callable fails to match')


def test_match_str_callable_mismatch():
    with pytest.raises(TF):
        tc_match_str(ps(), lambda x: x > 0, -999, 'callable matches incorrectly')


#-------------------------------------------------------------------------------
# Checking lists of files against file specs.


def test_files_empty_empty_passes():
    tc_check_files(ps(), 'CMD', [], [])


def test_files_empty_nonempty_fails():
    with pytest.raises(TF):
        tc_check_files(ps(), 'CMD', [], ['whoops'])


def test_files_nonempty_empty_fails():
    with pytest.raises(TF):
        tc_check_files(ps(), 'CMD', ['whoops'], [])


def test_files_text_match_succeeds():
    tc_check_files(ps(), 'CMD', ['a'], ['a'])


def test_files_text_mismatch_fails():
    with pytest.raises(TF):
        tc_check_files(ps(), 'CMD', ['a'], ['b'])


def test_files_text_lengthy_match_succeeds():
    tc_check_files(ps(), 'CMD', ['a', 'b'], ['a', 'b'])


def test_files_text_lengthy_mismatch_fails():
    with pytest.raises(TF):
        tc_check_files(ps(), 'CMD', ['b', 'a'], ['a', 'b'])


def test_files_text_overlong_expected_fails():
    with pytest.raises(TF):
        tc_check_files(ps(), 'CMD', ['a', 'b', 'c'], ['a', 'b'])


def test_files_text_overlong_actual_fails():
    with pytest.raises(TF):
        tc_check_files(ps(), 'CMD', ['a', 'b'], ['a', 'b', 'c'])


def test_files_regex_match_succeeds():
    tc_check_files(ps(), 'CMD', [rxc(r'ab+c')], ['abbbc'])


def test_files_regex_mismatch_fails():
    with pytest.raises(TF):
        tc_check_files(ps(), 'CMD', [rxc(r'ab+c')], ['b'])


def test_files_regex_trailing_match_succeeds():
    tc_check_files(ps(), 'CMD', ['x', rxc(r'ab+c')], ['x', 'abbbc'])


def test_files_regex_trailing_mismatch_fails():
    with pytest.raises(TF):
        tc_check_files(ps(), 'CMD', ['x', rxc(r'ab+c')], ['y', 'b'])


def test_files_callable_match_succeeds():
    tc_check_files(ps(), 'CMD', [lambda x: len(x) == 5], ['abbbc'])


def test_files_callable_mismatch_fails():
    with pytest.raises(TF):
        tc_check_files(ps(), 'CMD', [lambda x: len(x) == 5], ['b'])


def test_files_callable_trailing_match_succeeds():
    tc_check_files(ps(), 'CMD', ['x', lambda x: len(x) == 5], ['x', 'abbbc'])


def test_files_callable_trailing_mismatch_fails():
    with pytest.raises(TF):
        tc_check_files(ps(), 'CMD', ['x', lambda x: len(x) == 5], ['y', 'b'])


def test_files_singleton_set_match():
    tc_check_files(ps(), 'CMD', [{'x'}], ['x'])


def test_files_singleton_set_mismatch():
    with pytest.raises(TF):
        tc_check_files(ps(), 'CMD', [{'x'}], ['y'])


def test_files_double_set_match():
    tc_check_files(ps(), 'CMD', [{'x', 'y'}], ['x', 'y'])


def test_files_double_set_mismatch():
    with pytest.raises(TF):
        tc_check_files(ps(), 'CMD', [{'x', 'y'}], ['a', 'y'])


def test_files_set_with_leading_match():
    tc_check_files(ps(), 'CMD', ['a', {'x', 'y'}], ['a', 'x', 'y'])


def test_files_set_with_leading_mismatch():
    with pytest.raises(TF):
        tc_check_files(ps(), 'CMD', ['a', {'x', 'y'}], ['b', 'x', 'y'])


def test_files_set_with_trailing_match():
    tc_check_files(ps(), 'CMD', [{'x', 'y'}, 'a'], ['x', 'y', 'a'])


def test_files_set_with_trailing_mismatch():
    with pytest.raises(TF):
        tc_check_files(ps(), 'CMD', [{'x', 'y'}, 'a'], ['x', 'y', 'b'])


def test_files_set_with_leading_as_trailing_mismatch():
    with pytest.raises(TF):
        tc_check_files(ps(), 'CMD', ['a', {'x', 'y'}], ['x', 'y', 'a'])


#-------------------------------------------------------------------------------
# Checking actual command-line arguments against specs.


def test_constraints_empty_empty_passes():
    tc_check_constraints(ps(), 'CMD', {}, [])


def test_constraints_str_empty_nonempty_passes():
    tc_check_constraints(ps(), 'CMD', {}, [('-a', '1')])


def test_constraints_str_nonempty_empty_passes():
    tc_check_constraints(ps(), 'CMD', {'-a' : '1'}, [])


def test_constraints_str_single_match():
    tc_check_constraints(ps(), 'CMD', {'-a' : '1'}, [('-a', '1')])


def test_constraints_str_single_mismatch_option():
    tc_check_constraints(ps(), 'CMD', {'-a' : '1'}, [('-b', '1')])


def test_constraints_str_single_mismatch_arg():
    with pytest.raises(TF):
        tc_check_constraints(ps(), 'CMD', {'-a' : '1'}, [('-a', '999')])


def test_constraints_str_repeated_actual_match():
    tc_check_constraints(ps(), 'CMD', {'-a' : '1'}, [('-a', '1'), ('-a', '1')])


def test_constraints_str_repeated_actual_mismatch():
    with pytest.raises(TF):
        tc_check_constraints(ps(), 'CMD', {'-a' : '1'}, [('-a', '1'), ('-a', '999')])


def test_constraints_str_multiple_match():
    tc_check_constraints(ps(), 'CMD', {'-a' : '1', '-b' : '2'}, [('-a', '1'), ('-b', '2')])


def test_constraints_str_multiple_one_mismatch():
    with pytest.raises(TF):
        tc_check_constraints(ps(), 'CMD', {'-a' : '1', '-b' : '2'}, [('-a', '1'), ('-b', '999')])


def test_constraints_str_regex_match():
    tc_check_constraints(ps(), 'CMD', {'-a' : rxc(r'ab+c')}, [('-a', 'abbbc')])


def test_constraints_str_regex_mismatch():
    with pytest.raises(TF):
        tc_check_constraints(ps(), 'CMD', {'-a' : rxc(r'ab+c')}, [('-a', 'b')])


def test_constraints_everything_match():
    tc_check_constraints(ps(), 'CMD',
                         {'-a' : '1', '-b' : rxc(r'ab+c'), '-c' : lambda x: int(x) > 5, '-d' : 'xyz'},
                         [('-c', '99'), ('-b', 'abbbc'), ('-e', 'not checked')])


#-------------------------------------------------------------------------------
# Checking command names.


def test_command_name_match():
    remainder = tc_check_command(ps(), 'a', ['a'])
    assert remainder == [], 'Wrong remainder'


def test_command_name_mismatch():
    with pytest.raises(TF):
        tc_check_command(ps(), 'a', ['b'])


def test_command_multi_empty_fails():
    with pytest.raises(AssertionError):
        tc_check_command(ps(), [], ['a', '-b'])


def test_command_multi_match():
    remainder = tc_check_command(ps(), ['a', 'b'], ['a', 'b'])
    assert remainder == [], 'Wrong remainder'


def test_command_multi_mismatch():
    with pytest.raises(TF):
        tc_check_command(ps(), ['a', 'c'], ['a', 'b'])


def test_command_remainder_single():
    remainder = tc_check_command(ps(), 'a', ['a', 'b'])
    assert remainder == ['b'], 'Wrong remainder'


def test_command_remainder_multi():
    remainder = tc_check_command(ps(), ['a', 'b'], ['a', 'b', 'c', 'd'])
    assert remainder == ['c', 'd'], 'Wrong remainder'


#-------------------------------------------------------------------------------
# Checking a single chunk.


def test_chunk_command_name_only_match():
    tc_check_chunk(ps(),
                   ['a'],
                   'a'.split())


def test_chunk_command_name_only_mismatch():
    with pytest.raises(TF):
        tc_check_chunk(ps(),
                       ['a'],
                       'b'.split())


def test_chunk_no_options_allowed_match():
    tc_check_chunk(ps(),
                   ['a', None],
                   'a'.split())


def test_chunk_no_options_allowed_mismatch():
    with pytest.raises(AssertionError):
        tc_check_chunk(ps(),
                       ['a', None],
                       'a -b'.split())


def test_chunk_bare_option_match():
    tc_check_chunk(ps(),
                   ['a', 'b'],
                   'a -b'.split())


def test_chunk_bare_option_mismatch():
    with pytest.raises(AssertionError):
        tc_check_chunk(ps(),
                       ['a', 'b'],
                       'a -c'.split())


def test_chunk_bare_option_allowed():
    tc_check_chunk(ps(),
                   ['a', 'bc'],
                   'a -c'.split())


def test_chunk_arg_option_match():
    tc_check_chunk(ps(),
                   ['a', 'b:'],
                   'a -b xyz'.split())


def test_chunk_arg_option_value_match():
    tc_check_chunk(ps(),
                   ['a', 'b:', [], {'-b' : 'xyz'}],
                   'a -b xyz'.split())


def test_chunk_arg_option_value_mismatch():
    with pytest.raises(TF):
        tc_check_chunk(ps(),
                       ['a', 'b:', [], {'-b' : 'xyz'}],
                       'a -b pqr'.split())


def test_chunk_arg_option_value_pattern_match():
    tc_check_chunk(ps(),
                   ['a', 'b:', [], {'-b' : rxc(r'ab+c')}],
                   'a -b abbbc'.split())


def test_chunk_arg_option_value_pattern_mismatch():
    with pytest.raises(TF):
        tc_check_chunk(ps(),
                       ['a', 'b:', [], {'-b' : rxc(r'ab+c')}],
                       'a -b x'.split())


def test_chunk_filename_match():
    tc_check_chunk(ps(),
                   ['a', '', ['x']],
                   'a x'.split())


def test_chunk_filename_mismatch():
    with pytest.raises(TF):
        tc_check_chunk(ps(),
                       ['a', '', ['x']],
                       'a y'.split())


def test_chunk_multi_filename_match():
    tc_check_chunk(ps(),
                   ['a', '', ['x', 'y', rxc(r'zz+')]],
                   'a x y zzzzzzz'.split())


def test_chunk_multi_filename_mismatch():
    with pytest.raises(TF):
        tc_check_chunk(ps(),
                       ['a', '', ['x', 'y', rxc(r'zz+')]],
                       'a x y zqqz'.split())


def test_chunk_args_and_filenames_match():
    tc_check_chunk(ps(),
                   [['a', 'b'], 'c:d', ['p', {'q', 'r'}, 's'], {'-c' : 'NNN'}],
                   'a b -c NNN -d p r q s'.split())


def test_chunk_args_and_filenames_arg_mismatch():
    with pytest.raises(TF):
        tc_check_chunk(ps(),
                       [['a', 'b'], 'cd:', ['p', {'q', 'r'}, 's'], {'-c' : 'NNN'}],
                       'a b -c NNN -d p r q s'.split())


def test_chunk_args_and_filenames_filename_mismatch():
    with pytest.raises(TF):
        tc_check_chunk(ps(),
                       [['a', 'b'], 'c:d', ['p', 'q', 'r', 's'], {'-c' : 'NNN'}],
                       'a b -c NNN -d p r q s'.split())


#-------------------------------------------------------------------------------
# Check that optional pipeline elements are handled correctly.


def test_optional_absent_unneeded():
    assert tc_handle_optional(ps(), [['a']], [['a']]) == ([['a']], [['a']])


def test_optional_absent_needed():
    with pytest.raises(TF):
        assert tc_handle_optional(ps(), [['a']], [['a'], ['b']])


def test_optional_present_unneeded():
    assert tc_handle_optional(ps(), [['a'], Optional()], [['a']]) == ([['a']], [['a']])


def test_optional_present_needed():
    assert tc_handle_optional(ps(), [['a'], Optional()], [['a'], ['b']])


def test_optional_present_still_too_short():
    with pytest.raises(TF):
        assert tc_handle_optional(ps(), [['a'], Optional()], [['a'], ['b'], ['c']])


#-------------------------------------------------------------------------------
# Checking command-line parsing.


def test_parse_cmdline_single_bare_command():
    assert tc_parse_cmdline(ps('a')) == ([['a']], None)


def test_parse_cmdline_double_bare_commands():
    assert tc_parse_cmdline(ps('a | b')) == ([['a'], ['b']], None)


def test_parse_cmdline_single_command_with_args():
    assert tc_parse_cmdline(ps('a -b')) == ([['a', '-b']], None)


def test_parse_cmdline_single_command_with_redirect():
    assert tc_parse_cmdline(ps('a > b')) == ([['a']], 'b')


def test_parse_cmdline_pipe_with_redirect():
    assert tc_parse_cmdline(ps('a|b -c -d  "eee"  | f g  -h > z')) \
        == \
        ([['a'], ['b', '-c', '-d', 'eee'], ['f', 'g', '-h']], 'z')


def test_parse_cmdline_leading_redirect():
    with pytest.raises(TF):
        tc_parse_cmdline(ps('> b'))


def test_parse_cmdline_trailing_redirect():
    with pytest.raises(TF):
        tc_parse_cmdline(ps('b >'))


def test_parse_cmdline_pipe_after_redirect():
    with pytest.raises(TF):
        tc_parse_cmdline(ps('b > c | d'))


def test_parse_cmdline_multiple_redirect():
    with pytest.raises(TF):
        tc_parse_cmdline(ps('b > c > d'))


def test_parse_cmdline_last_line_flag_not_set():
    with pytest.raises(TF):
        assert tc_parse_cmdline(ps('a\nb'))


def test_parse_cmdline_last_line_flag_set():
    assert tc_parse_cmdline(ps('a\nb'), last_line_only=True) == ([['b']], None)


#-------------------------------------------------------------------------------
# Test the whole thing.

def test_cmdline_example():
    _test_cmdline(ps('\n# a comment\nextract params.txt data/b.csv data/a.csv | sort -n | tail -n 3 > last.csv\n'),
                 [['extract', '', [rxc(r'p.+\.txt'), {'data/a.csv', 'data/b.csv'}]],
                  ['sort', 'n'],
                  ['tail', 'n:', [], {'-n' : '3'}]],
                 'Use extract, sort, and tail with redirection.',
                 redirect_out=re.compile(r'.+\.csv'),
                 last_line_only=True)
