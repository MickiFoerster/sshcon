sshcon_lib = static_library(
  'sshcon',
  sources: ['sshcon.c'],
  include_directories: include_directories('../include'),
  dependencies: [meson.get_compiler('c').find_library('ssh2')],
  c_args: ['-std=c11', '-Wall', '-Werror'],
)

executable(
  'main',
  sources: ['main.c'],
  include_directories: include_directories('../include'),
  link_with: sshcon_lib,
)
