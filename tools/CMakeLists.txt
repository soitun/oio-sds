add_definitions(-DG_LOG_DOMAIN="oio.tools")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE
	${CMAKE_SOURCE_DIR}
	${CMAKE_BINARY_DIR})

include_directories(AFTER
	${ZK_INCLUDE_DIRS})

link_directories(
	${JSONC_LIBRARY_DIRS}
	${SQLITE3_LIBRARY_DIRS})

add_executable(oio-zk-harass oio-zk-harass.c)
bin_prefix(oio-zk-harass -zk-harass)
target_link_libraries(oio-zk-harass
	metautils sqliterepo
	${ZK_LIBRARIES} ${GLIB2_LIBRARIES})

add_executable(oio-tool oio-tool.c)
bin_prefix(oio-tool -tool)
target_link_libraries(oio-tool
	oiocore metautils
	server hcresolve oioevents
	sqliterepo sqlitereporemote
	meta2v2utils
	${GLIB2_LIBRARIES})

add_executable(oio-file oio-file.c)
bin_prefix(oio-file -file-tool)
target_link_libraries(oio-file
		oiosds ${GLIB2_LIBRARIES})

add_executable(oio-lb-benchmark oio-lb-benchmark.c)
bin_prefix(oio-lb-benchmark -lb-benchmark)
target_link_libraries(oio-lb-benchmark
		oiocore metautils
		${GLIB2_LIBRARIES})

add_custom_target(oio-rawx-harass ALL)
set(GO_BUILD_RAWX_HARASS ${GO_EXECUTABLE} build -o ${CMAKE_CURRENT_BINARY_DIR}/oio-rawx-harass oio-rawx-harass.go)

add_custom_command(
	TARGET oio-rawx-harass
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/oio-rawx-harass.go
	COMMAND
	cd ${CMAKE_CURRENT_SOURCE_DIR} && ${GO_BUILD_RAWX_HARASS}
	COMMENT
		"Build oio-rdir-harass tool, written in Golang"
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/oio-sds.pc.in
	${CMAKE_CURRENT_BINARY_DIR}/oio-sds.pc @ONLY)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/oio-bootstrap.py
	${CMAKE_CURRENT_BINARY_DIR}/oio-bootstrap.py @ONLY)

install(FILES
			${CMAKE_CURRENT_BINARY_DIR}/oio-sds.pc
		DESTINATION ${PKGCONFIG_DIRECTORY}
		PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install(TARGETS
			oio-tool
			oio-lb-benchmark
		DESTINATION bin)

install(TARGETS
			oio-file
			oio-zk-harass
		DESTINATION bin
		CONFIGURATIONS Debug)

install(PROGRAMS
			oio-flush-all.sh
			oio-wait-scored.sh
			${CMAKE_CURRENT_BINARY_DIR}/oio-bootstrap.py
			oio-test-config.py
			oio-reset.sh
			oio-dump-buried-events.py
			openioctl.sh
		DESTINATION bin
		CONFIGURATIONS Debug)

