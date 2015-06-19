# check_gorpe
Script to execute GORPE checks and return their exit code

```
$ ./check_gorpe -H localhost -c / -debug
DEBUG Trying to GET https://localhost:5666//[]
DEBUG outArray:[[GORPE version 1.0 Build time: 2015-06-19 12:33:01|gorpe_uptime=408.1s Result Code: 0 ]]
DEBUG len(outArray):[3]
DEBUG returnCodeLine:[Result Code: 0]
DEBUG returnCode:[0]
DEBUG exitCode:[0]
GORPE version 1.0 Build time: 2015-06-19 12:33:01|gorpe_uptime=408.1s
$ echo $?
0
```
