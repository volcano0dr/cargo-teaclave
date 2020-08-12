# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
Rust_Name := cargo-teaclave
Rust_Files := $(wildcard src/*.rs)
Vendor_Path := ./vendor
Build_Out_Path := ./out

.PHONY: all

all: $(Rust_Name)

$(Rust_Name): $(Rust_Files)
	cargo build --release
	cp ./target/release/$(Rust_Name) ~/.cargo/bin/$(Rust_Name)


.PHONY: clean
clean:
	@rm -rf $(Vendor_Path) $(Build_Out_Path)
	@rm -f ~/.cargo/bin/$(Rust_Name)
	@cargo clean
