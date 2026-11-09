import { useEffect, useState } from "react";
import { ActionGroup, Alert, Button, FormGroup } from "@patternfly/react-core";
import { useAccess } from "../../context/access/Access";
import { useAdminClient } from "../../admin-client";
import { useRealm } from "../../context/realm-context/RealmContext";

type Result = { success: boolean; code: string; message: string; status: number | null };

export function ScimConnectionTest({ componentId, isDirty }: { componentId?: string; isDirty: boolean }) {
  const { adminClient, keycloak } = useAdminClient();
  const { realm } = useRealm();
  const { hasAccess } = useAccess();
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<Result>();
  // A result belongs to the saved form that was tested, and disappears on edit.
  const [testedComponent, setTestedComponent] = useState<string>();
  useEffect(() => { setResult(undefined); }, [isDirty, componentId]);
  const test = async () => {
    setTesting(true);
    setResult(undefined);
    try {
      await keycloak.updateToken(30);
      const response = await fetch(`${adminClient.baseUrl}/admin/realms/${encodeURIComponent(realm)}/scim-outbound/${encodeURIComponent(componentId!)}/test-connection`, {
        method: "POST",
        headers: { Authorization: `Bearer ${keycloak.token}`, Accept: "application/json" },
        cache: "no-store",
        signal: AbortSignal.timeout(15000),
      });
      if (!response.ok) {
        throw new Error(response.status === 403 ? "You do not have permission to test this connection." : "The connection test could not be completed. Refresh the page and try again.");
      }
      setResult(await response.json());
      setTestedComponent(componentId);
    } catch (error) {
      setResult({ success: false, code: "REQUEST_FAILED", status: null,
        message: error instanceof Error && error.name !== "TimeoutError" ? error.message : "The connection test timed out. Try again." });
      setTestedComponent(componentId);
    } finally { setTesting(false); }
  };
  return <FormGroup label="Connection test" fieldId="scim-connection-test-group">
    <ActionGroup>
      <Button id="scim-test-connection" variant="secondary" isLoading={testing}
        isDisabled={testing || isDirty || !componentId || !hasAccess("manage-realm")}
        onClick={test}>Test connection</Button>
    </ActionGroup>
    {(!componentId || isDirty) && <p>Save changes before testing the connection.</p>}
    {!isDirty && result && testedComponent === componentId &&
      <Alert isInline variant={result.success ? "success" : "danger"}
        title={result.success ? "Connection successful" : "Connection failed"}>
        <p>{result.message}</p>
      </Alert>}
  </FormGroup>;
}
