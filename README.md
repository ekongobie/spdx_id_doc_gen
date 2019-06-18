# SPDXID spdx document generator #

## Specs ##
* Python 3

1. ### Create virtualenv ###
`python3 -m venv spdx_id_env`

2. ### Go to virtualenv ###
`cd spdx_id_env`

3. ### Clone repo ###
`git clone https://github.com/ekongobie/spdx_id_doc_gen.git`

4. ### Activate virtualenv ###
`source bin/activate`

5. ### go to package folder ###
`cd spdx_id_doc_gen`

6. ### Install requirements ###
`pip install -r requirements.txt`

7. ### Install package ###
`pip install -e .`

7. ### Generate spdx doc for packages ###
`spdxgen ~/path/to/package/folder tv`

