// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// The delegation-chain link a session carries (SessionManager). The Helix
// VP and its verification types are gone (KYA-OS story C-C).

export interface DelegationLink {
  issuer: string;
  subject: string;
  vcId: string;
  scopes: string[];
  delegationDepth: number;
}
