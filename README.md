# Minimal implementation of getting CERN SSO cookies

## Installation

```
pip install minimal-cernsso
```

or

```
git clone https://github.com/tklijnsma/minimal-cernsso.git
pip install -e minimal-cernsso
```


## Getting certificate files

1. Get a valid `myCertificate.p12` as issued by https://ca.cern.ch/ca/. You can create a new one (`New Grid User certificate`), or use one you have previously created. If you create a new one, for simplicity's sake, do not give it a password, it will be deleted in the steps below anyway.

2. Run the following commands:

```
# Import password is empty if you did not give it a password on https://ca.cern.ch/ca/
openssl pkcs12 -clcerts -nokeys -in myCertificate.p12 -out myCert.pem

# Import password should still be empty; PEM pass phrase may NOT be empty. Just enter anything, e.g. 'password'
openssl pkcs12 -nocerts -in myCertificate.p12 -out myCert.tmp.key

# Enter whatever PEM pass phrase you entered in the previous step. myCert.key will NOT be password protected.
openssl rsa -in myCert.tmp.key -out myCert.key

# Remove the tmp and set permissions
rm myCert.tmp.key
chmod 644 myCert.pem
chmod 400 myCert.key
```

Note the final key file `myCert.key` is NOT password protected - it is equivalent to your CERN password. So store it safely!


## Using this package

On the command line, you can do:

```
cernsso-get-cookies https://some-protected-url.cern.ch/ -c /path/to/myCert.pem -k /path/to/myCert.key
```

This will create a file `cookies.txt`, which can subsequently be used to request further information behind CERN SSO.

You can simply use `curl`:

```
curl -L --cookie cookies.txt --cookie-jar cookies.txt --insecure "https://some-protected-url.cern.ch/the/resource/you/want?parameter"
```

Or you can get a `request.Session` object in python:

```
import minimal-cernsso as cernsso

s = cernsso.session_from_cookies_file('/path/to/myCert.pem', '/path/to/myCert.key')

r = s.get('https://some-protected-url.cern.ch/the/resource/you/want?parameter', verify=False)
```

Note you must always add `verify=False` for requests made with this session object (since the CERN Root certificate isn't recognized by default by the `requests` package), so only make requests to resources you trust!


## Example: MCM

```
cernsso-get-cookies https://cms-pdmv.cern.ch/mcm/search -c path/to/myCert.pem -k path/to/myCert.key

curl -L --cookie cookies.txt --cookie-jar cookies.txt --insecure "https://cms-pdmv.cern.ch/mcm/search?db_name=requests&produce=/QCD_Pt_1400to1800_TuneCP5_13TeV_pythia8/RunIIAutumn18MiniAOD-102X_upgrade2018_realistic_v15-v1/MINIAODSIM&page=0&get_raw"

# or, in python:

import minimal-cernsso as cernsso
s = cernsso.session_from_cookies_file('/path/to/myCert.pem', '/path/to/myCert.key')
r = s.get(
    'https://cms-pdmv.cern.ch/mcm/search?'
    'db_name=requests'
    '&produce=/QCD_Pt_1400to1800_TuneCP5_13TeV_pythia8/RunIIAutumn18MiniAOD-102X_upgrade2018_realistic_v15-v1/MINIAODSIM'
    '&page=0'
    '&get_raw'
    .format(dataset),
    verify=False
    )
r.raise_for_status()
d = r.json()
print(d)
```
