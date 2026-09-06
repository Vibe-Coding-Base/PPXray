// Opening a .ppx profile, shared by the two places that offer it.
//
// The profile bar has an "Open" button and the empty state has a primary
// call-to-action; both need the same picker, the same store write and the
// same notification. Kept in its own file rather than exported alongside a
// component, so fast refresh keeps working.

import { notifications } from "@mantine/notifications";
import { useCallback, useState } from "react";

import { pickAndOpenProfile } from "@/ipc/profile";
import { useProfileStore } from "@/stores/profile-store";

export function useOpenProfile() {
  const setLoaded = useProfileStore((s) => s.setLoaded);
  const [opening, setOpening] = useState(false);

  const open = useCallback(async () => {
    setOpening(true);
    try {
      const result = await pickAndOpenProfile();
      // A cancelled picker is a normal outcome, not a failure to report.
      if (!result) return;
      setLoaded(result.profile, result.path);
      notifications.show({
        title: "Profile loaded",
        message: `${result.profile.rules.length} rules, ${result.profile.proxies.length} proxies`,
        color: "teal",
      });
    } catch (err) {
      notifications.show({
        title: "Failed to open profile",
        message: String(err),
        color: "red",
      });
    } finally {
      setOpening(false);
    }
  }, [setLoaded]);

  return { open, opening };
}
