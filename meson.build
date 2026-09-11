project('libmobile-bgb', 'c',
  version : '0.2.0',
  default_options : [
    'warning_level=2',
    'c_std=gnu11'])

cc = meson.get_compiler('c')
c_args = []
link_args = []
deps = []

# Enable -ffunction-sections -fdata-sections and -Wl,--gc-sections by default
if cc.has_link_argument('-Wl,--gc-sections')
  add_global_arguments(['-ffunction-sections', '-fdata-sections'], language : 'c')
  add_global_link_arguments('-Wl,--gc-sections', language : 'c')
endif

# Link relevant libraries
deps += dependency('libmobile', version : '>=0.2.0', static : true)

if host_machine.system() == 'windows'
  deps += cc.find_library('ws2_32')
  deps += cc.find_library('advapi32')
  c_args += ['-DUNICODE', '-D_UNICODE', '-D_WIN32_WINNT=0x0501']
  c_args += ['-D_CRT_SECURE_NO_WARNINGS']

  # Without this, the PE header's link timestamp changes every build even
  # with byte-identical source, making a release's published checksum
  # unreproducible and impossible to tell apart from a tampered file.
  if cc.has_link_argument('-Wl,--no-insert-timestamp')
    link_args += ['-Wl,--no-insert-timestamp']
  endif
endif

executable('mobile',
  'source/bgblink.c',
  'source/bgblink.h',
  'source/device_auth.c',
  'source/device_auth.h',
  'source/main.c',
  'source/socket.c',
  'source/socket.h',
  'source/socket_impl.c',
  'source/socket_impl.h',
  c_args : c_args,
  link_args : link_args,
  dependencies : deps,
  install : true)
