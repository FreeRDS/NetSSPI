# Network Security Support Provider Interface (NetSSPI)
#
# Copyright 2012-2013 Marc-Andre Moreau <marcandre.moreau@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set(MODULE_NAME "netsspi-server")
set(MODULE_PREFIX "NETSSPI_SERVER")

include_directories(${WinPR_INCLUDE_DIR})
	
set(${MODULE_PREFIX}_SRCS
	../netsspi.c
	netsspi_server.c)

add_executable(${MODULE_NAME} ${${MODULE_PREFIX}_SRCS})

set(${MODULE_PREFIX}_LIBS "")
	
if(WIN32)
	list(APPEND ${MODULE_PREFIX}_LIBS ws2_32)
	list(APPEND ${MODULE_PREFIX}_LIBS setupapi)
endif()

if(WinPR_MONOLITHIC_BUILD)
	list(APPEND ${MODULE_PREFIX}_LIBS winpr)
else()
	list(APPEND ${MODULE_PREFIX}_LIBS winpr-crt winpr-sspi winpr-utils)
endif()

target_link_libraries(${MODULE_NAME} ${${MODULE_PREFIX}_LIBS})
