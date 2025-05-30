add_definitions(-DG_LOG_DOMAIN="oio.tests.func")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

include_directories(BEFORE
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_BINARY_DIR})

include_directories(AFTER
		${GLIB2_INCLUDE_DIRS}
		${CURL_INCLUDE_DIRS}
		${JSONC_INCLUDE_DIRS})

link_directories(
		${GLIB2_LIBRARY_DIRS}
		${CURL_LIBRARY_DIRS}
		${JSONC_LIBRARY_DIRS})

add_library(oiosds_test SHARED testlib_sds.c)
set_target_properties(oiosds_test PROPERTIES VERSION 0.0.0 SOVERSION 0)
target_link_libraries(oiosds_test oiosds)
add_test(NAME core/sds
		COMMAND /usr/bin/env ${PYTHON} -m coverage run --context func-c -p ${CMAKE_CURRENT_SOURCE_DIR}/test_oiosds.py ${CMAKE_CURRENT_BINARY_DIR})
set_tests_properties(core/sds PROPERTIES ENVIRONMENT CTEST_OUTPUT_ON_FAILURE=1)

add_library(oiohttp_test SHARED testlib_http.c)
set_target_properties(oiohttp_test PROPERTIES VERSION 0.0.0 SOVERSION 0)
target_link_libraries(oiohttp_test oiosds)
add_test(NAME core/http
		COMMAND /usr/bin/env ${PYTHON} -m coverage run --context func-c -p ${CMAKE_CURRENT_SOURCE_DIR}/test_oiohttp.py ${CMAKE_CURRENT_BINARY_DIR})
set_tests_properties(core/http PROPERTIES ENVIRONMENT CTEST_OUTPUT_ON_FAILURE=1)

add_executable(test_oio_cs test_cs.c)
target_link_libraries(test_oio_cs oiocore gridcluster)
add_test(NAME core/cs COMMAND test_oio_cs)

add_executable(test_oio_dir test_dir.c)
target_link_libraries(test_oio_dir oiosds)
add_test(NAME core/dir COMMAND test_oio_dir)

add_executable(test_weird_chars test_weird_chars.c)
target_link_libraries(test_weird_chars oiosds oiocore)
add_test(NAME core/sds/weird_chars COMMAND test_weird_chars)

add_executable(test_oio_cluster test_cluster.c)
target_link_libraries(test_oio_cluster oiocore gridcluster)
add_test(NAME cluster/lib COMMAND test_oio_cluster)

add_executable(test_old_c_api test_old_c_api.c)
target_link_libraries(test_old_c_api oiocore gridcluster)
add_test(NAME core/sds/old COMMAND test_oio_cluster)

