/**
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

resource "google_scc_event_threat_detection_custom_module" "iam_deny_permissions" {
  organization     = var.organization
  display_name     = "iam_deny_permissions_module"
  enablement_state = "ENABLED"
  type             = "CONFIGURABLE_CUSTOM_ROLE_WITH_PROHIBITED_PERMISSION"
  config = jsonencode({
    "metadata" : {
      "severity" : "LOW",
      "description" : "IAM permissions which are part of the IAM Deny list have been created and/or granted",
      "recommendation" : "IAM permissions which are part of the IAM Deny list have been created and/or granted. It is recommended to remove these permissions in order to meet Apple’s security policy."
    },
    "permissions" : [
      "iam.serviceAccounts.getAccessToken",
      "iam.serviceAccounts.getOpenIdToken",
      "iam.serviceAccounts.actAs",
      "iam.serviceAccounts.signBlob",
      "iam.serviceAccounts.signJwt"
    ]
    }
  )
}

resource "google_scc_mute_config" "permissions_mute" {
  mute_config_id = "mute-permissions-config"
  parent         = "projects/${var.project}"
  filter         = "module_name=\"${google_scc_event_threat_detection_custom_module.iam_deny_permissions.id}\""
  description    = "Mute IAM Deny Permissions"
}

resource "google_scc_event_threat_detection_custom_module" "iam_deny_roles" {
  organization     = var.organization
  display_name     = "iam_deny_roles_module"
  enablement_state = "ENABLED"
  type             = "CONFIGURABLE_UNEXPECTED_ROLE_GRANT"
  config = jsonencode({
    "metadata" : {
      "severity" : "LOW",
      "description" : "Predefined Roles which contain IAM permissions which are restrict by IAM Deny have been granted.",
      "recommendation" : "As a project Owner, review and/or remove the assigned Predefined role."
    },
    "roles" : [
      "roles/iam.workloadIdentityUser"
    ]
    }
  )
}

resource "google_scc_mute_config" "roles_mute" {
  mute_config_id = "mute-roles-config"
  parent         = "projects/${var.project}"
  filter         = "module_name=\"${google_scc_event_threat_detection_custom_module.iam_deny_roles.id}\""
  description    = "Mute IAM Deny Roles"
}