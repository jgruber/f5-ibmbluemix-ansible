BASIC-LAUNCH
=========

A basic template launch wherein the variables are statically defined.
Default values are in defaults/main.yml

Requirements
------------

- /etc/ansible/hosts should exist
- tested with default ansible configs
- openstackrc file must include password value

Role Variables
--------------
stack_name: name to apply to the stack to be created
template_path: path relative to parent dir to the heat template file
env_file_path: path related to parent dir to the heat environment file

Dependencies
------------

shade 1.8 or higher
heat-client 1.4 or higher (otherwise, there is an error with client manager)


License
-------

BSD

Author Information
------------------

An optional section for the role authors to include contact information, or a website (HTML is not allowed).
