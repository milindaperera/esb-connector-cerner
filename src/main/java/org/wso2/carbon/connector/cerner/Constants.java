/*
 *  Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied. See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.connector.cerner;

/**
 * This class holds constants related to CERNER connector
 */
public class Constants {

    public static final String CERNER_ACCESS_TOKEN = "accessToken";
    public static final String CERNER_CLIENT_ID = "clientId";
    public static final String CERNER_CLIENT_SECRET = "clientSecret";
    public static final String CERNER_TOKEN_EP = "tokenEndpoint";
    public static final String CERNER_SCOPES = "scopes";

    public static final String CERNER_PROPERTY_ACCESS_TOKEN = "_CONNECTOR_INTERNAL_CERNER_ACCESS_TOKEN_";
    public static final String CERNER_PROPERTY_CLIENT_ID = "_CONNECTOR_INTERNAL_CERNER_CLIENT_ID_";
    public static final String CERNER_PROPERTY_TOKEN_ENDPOINT = "_CONNECTOR_INTERNAL_CERNER_TOKEN_ENDPOINT_";

    /**
     * This is default scope set. Contain all the scopes available at the application creation phase in cerner
     */
    public static final String CERNER_DEFAULT_SCOPES = "system%2FAllergyIntolerance.read+" +
            "system%2FAllergyIntolerance.write+system%2FAppointment.read+system%2FAppointment.write+" +
            "system%2FBinary.read+system%2FCarePlan.read+system%2FCondition.read+system%2FCondition.write+" +
            "system%2FContract.read+system%2FDevice.read+system%2FDiagnosticReport.read+" +
            "system%2FDocumentReference.read+system%2FDocumentReference.write+system%2FEncounter.read+" +
            "system%2FGoal.read+system%2FImmunization.read+system%2FMedicationAdministration.read+" +
            "system%2FMedicationOrder.read+system%2FMedicationStatement.read+system%2FMedicationStatement.write+" +
            "system%2FObservation.read+system%2FPatient.read+system%2FPatient.write+system%2FPerson.read+" +
            "system%2FPractitioner.read+system%2FProcedure.read+system%2FProcedureRequest.read+" +
            "system%2FRelatedPerson.read+system%2FSchedule.read+system%2FSlot.read";

}
