include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
project(NONE)

target_sources(app PRIVATE
  src/main.c
  src/rpl.c
)

zephyr_library_include_directories($ENV{ZEPHYR_BASE}/samples/bluetooth)

include($ENV{ZEPHYR_BASE}/samples/net/common/common.cmake)

target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/subsys/net/ip)
