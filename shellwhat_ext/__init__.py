def test_compare_lines(state, actualFilename, expectFilename):
    '''Check if two files are line-by-line equal (ignoring whitespace
    at the start and end of each line).'''

    try:
        with open(actualFilename, 'r') as stream:
            actualList = stream.readlines()
    except Exception as err:
        state.do_test('Unable to open user file {}'.format(actualFilename))

    try:
        with open(expectFilename, 'r') as stream:
            expectList = stream.readlines()
    except Exception as err:
        state.do_test('Unable to open reference file {}'.format(actualFilename))

    actualLen = len(actualList)
    expectLen = len(expectList)
    if actualLen != expectLen:
        msg = 'File {} has wrong length: got {} expected {}'
        state.do_test(msg.format(actualFilename, actualLen, expectLen))

    actualList = [x.strip() for x in actualList]
    expectList = [x.strip() for x in expectList]
    diffs = []
    for (i, actualLine, expectLine) in zip(range(len(actualList)), actualList, expectList):
        if actualLine != expectLine:
            diffs.append(i+1)

    if diffs:
        msg = 'Line(s) in {} not as expected: {}'
        state.do_test(msg.format(actualFilename, ', '.join([str(x) for x in diffs])))

    return state # all good
