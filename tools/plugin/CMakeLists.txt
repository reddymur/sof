# SPDX-License-Identifier: BSD-3-Clause

cmake_minimum_required(VERSION 3.13)

project(SOF_PLUGIN C)

include(../../scripts/cmake/misc.cmake)

set(sof_source_directory "${PROJECT_SOURCE_DIR}/../..")
set(sof_install_directory "${PROJECT_BINARY_DIR}/sof_ep/install")
set(sof_binary_directory "${PROJECT_BINARY_DIR}/sof_ep/build")

set(config_h ${sof_binary_directory}/library_autoconfig.h)

set(parser_source_directory "${PROJECT_SOURCE_DIR}/../tplg_parser")
set(parser_install_dir "${PROJECT_BINARY_DIR}/sof_parser/install")

add_executable(sof-pipe
	sof-pipe.c
	plugin.c
)

sof_append_relative_path_definitions(sof-pipe)
target_include_directories(sof-pipe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_compile_options(sof-pipe PRIVATE -DPIC -g -O3 -Wl,-EL -Wmissing-prototypes
  -Wimplicit-fallthrough -DCONFIG_LIBRARY -imacros${config_h})
  
 target_include_directories(sof-pipe PRIVATE ${sof_install_directory}/include)
target_include_directories(sof-pipe PRIVATE ${parser_install_dir}/include)
  
target_link_libraries(sof-pipe PRIVATE sof_library)
target_link_libraries(sof-pipe PRIVATE sof_parser_lib)
target_link_libraries(sof-pipe PRIVATE pthread)
target_link_libraries(sof-pipe PRIVATE  -lasound -ldl -lm -lasound)

# PCM module
add_library(asound_module_pcm_sof MODULE
	pcm_sof.c
	plugin.c
	topology.c
)
sof_append_relative_path_definitions(asound_module_pcm_sof)
target_include_directories(asound_module_pcm_sof PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_compile_options(asound_module_pcm_sof PRIVATE -DPIC -g -O3 -Wl,-EL -Wmissing-prototypes
  -Wimplicit-fallthrough -DCONFIG_LIBRARY -imacros${config_h})
  
install(TARGETS asound_module_pcm_sof DESTINATION /usr/lib/x86_64-linux-gnu/alsa-lib)

target_link_options(asound_module_pcm_sof PRIVATE -Wl,--export-dynamic,--no-undefined)
target_link_libraries(asound_module_pcm_sof PRIVATE sof_library)
target_link_libraries(asound_module_pcm_sof PRIVATE sof_parser_lib)
target_link_libraries(asound_module_pcm_sof PRIVATE pthread)
target_link_libraries(asound_module_pcm_sof PRIVATE  -lasound -ldl -lm -lasound)

target_include_directories(asound_module_pcm_sof PRIVATE ${sof_install_directory}/include)
target_include_directories(asound_module_pcm_sof PRIVATE ${parser_install_dir}/include)

set_target_properties(asound_module_pcm_sof
	PROPERTIES
	INSTALL_RPATH "${sof_install_directory}/alsa-lib"
	INSTALL_RPATH_USE_LINK_PATH TRUE
)

# CTL module
add_library(asound_module_ctl_sof MODULE
	ctl_sof.c
	plugin.c
	topology.c
)
sof_append_relative_path_definitions(asound_module_ctl_sof)
target_include_directories(asound_module_ctl_sof PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_compile_options(asound_module_ctl_sof PRIVATE -DPIC -g -O3 -Wl,-EL -Wmissing-prototypes
  -Wimplicit-fallthrough -DCONFIG_LIBRARY -imacros${config_h})
  
install(TARGETS asound_module_ctl_sof DESTINATION /usr/lib/x86_64-linux-gnu/alsa-lib)

target_link_options(asound_module_ctl_sof PRIVATE -Wl,--export-dynamic,--no-undefined)
target_link_libraries(asound_module_ctl_sof PRIVATE sof_library)
target_link_libraries(asound_module_ctl_sof PRIVATE sof_parser_lib)
target_link_libraries(asound_module_ctl_sof PRIVATE pthread)
target_link_libraries(asound_module_ctl_sof PRIVATE  -lasound -ldl -lm -lasound)

target_include_directories(asound_module_ctl_sof PRIVATE ${sof_install_directory}/include)
target_include_directories(asound_module_ctl_sof PRIVATE ${parser_install_dir}/include)

set_target_properties(asound_module_ctl_sof
	PROPERTIES
	INSTALL_RPATH "${sof_install_directory}/alsa-lib"
	INSTALL_RPATH_USE_LINK_PATH TRUE
)

#target_compile_options(asound_module_pcm_sof PRIVATE -g -O3 -Wall -Werror -Wl,-EL -Wmissing-prototypes
#  -Wimplicit-fallthrough -DCONFIG_LIBRARY -imacros${config_h})

install(FILES 50-sof.conf DESTINATION /usr/share/alsa/alsa.conf.d)
# HACK needs to link to above
install(FILES 50-sof.conf DESTINATION /etc/alsa/conf.d)

include(ExternalProject)

# External project for SOF library
ExternalProject_Add(sof_ep
	DOWNLOAD_COMMAND ""
	SOURCE_DIR "${sof_source_directory}"
	PREFIX "${PROJECT_BINARY_DIR}/sof_ep"
	BINARY_DIR "${sof_binary_directory}"
	CMAKE_ARGS -DCONFIG_LIBRARY=ON
		-DCMAKE_INSTALL_PREFIX=${sof_install_directory}
		-DCMAKE_VERBOSE_MAKEFILE=${CMAKE_VERBOSE_MAKEFILE}
		-DINIT_CONFIG=library_defconfig
		-DCONFIG_H_PATH=${config_h}
		-DCONFIG_LIBRARY_STATIC=ON
		-DOPTIMIZE_FOR_DEBUG=ON
	BUILD_ALWAYS 1
	BUILD_BYPRODUCTS "${sof_install_directory}/lib/libsof.a"
)

add_library(sof_library STATIC IMPORTED)
set_target_properties(sof_library PROPERTIES IMPORTED_LOCATION "${sof_install_directory}/lib/libsof.a")
add_dependencies(sof_library sof_ep)

# External project for topology parser
ExternalProject_Add(parser_ep
	SOURCE_DIR "${parser_source_directory}"
	PREFIX "${PROJECT_BINARY_DIR}/sof_parser"
	BINARY_DIR "${PROJECT_BINARY_DIR}/sof_parser/build"
	CMAKE_ARGS -DCONFIG_LIBRARY=ON
		-DCMAKE_INSTALL_PREFIX=${PROJECT_BINARY_DIR}/sof_parser/install
		-DCMAKE_VERBOSE_MAKEFILE=${CMAKE_VERBOSE_MAKEFILE}
		-DCONFIG_LIBRARY_STATIC=ON
		-DOPTIMIZE_FOR_DEBUG=ON
	BUILD_ALWAYS 1
	BUILD_BYPRODUCTS "${parser_install_dir}/lib/libsof_tplg_parser.a"
)

add_library(sof_parser_lib STATIC IMPORTED)
set_target_properties(sof_parser_lib PROPERTIES IMPORTED_LOCATION "${parser_install_dir}/lib/libsof_tplg_parser.a")
add_dependencies(sof_parser_lib parser_ep)

add_dependencies(asound_module_pcm_sof sof_parser_lib)
add_dependencies(asound_module_ctl_sof sof_parser_lib)


