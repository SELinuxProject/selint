# Copyright 2019 Tresys Technology, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

SOURCES=selint.adoc

if HAVE_ASCIIDOCTOR
man1_MANS=$(MANPAGES)
EXTRA_DIST=$(man1_MANS) $(SOURCES)
CLEANFILES=$(MANPAGES)

selint.1: $(SOURCES)
	$(ASCIIDOCTOR) --failure-level INFO --warnings --verbose --backend manpage $^ --out-file $@
else
EXTRA_DIST=$(SOURCES)
endif
