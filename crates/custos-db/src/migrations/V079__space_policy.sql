-- V079: the six simplespace policy columns become one `$type`-discriminated space policy.
--
-- `policy` is the normalized JSON policy object (known fields only, defaults filled) for a space
-- this host is the authority for, and NULL for a space it only keeps members' repos in, exactly
-- as the old `policy` column was. `policy_type` is generated from its `$type` for filtering.
--
-- Old rows convert with the reference's `configToPolicy` mapping (its migration
-- `006-space-policy.ts`); nothing is reset:
--   * a managing app on either side -> managedspace{managingApp, publishPolicy:false}, and the
--     space's member rows are dropped (the member list belongs to memberspace);
--   * everything else -> memberspace{publicRead, publicWrite, allowedApps (only under
--     allowList), publishPolicy:false, publishMembers:false}. An `app_allowed` that is not a JSON
--     array becomes [], which admits no app, so no space opens up by accident.
-- Records, LtHash state, writers and registrations stay as they are. The publish flags start
-- false, so no policy or member record needs backfilling.

ALTER TABLE spaces RENAME COLUMN policy TO read_policy;
ALTER TABLE spaces ADD COLUMN policy TEXT;

UPDATE spaces SET policy = CASE
    WHEN COALESCE(managing_app, write_managing_app) IS NOT NULL THEN json_object(
        '$type', 'com.atproto.managedspace.policy',
        'managingApp', COALESCE(managing_app, write_managing_app),
        'publishPolicy', json('false'))
    ELSE json_patch(
        json_object(
            '$type', 'com.atproto.memberspace.policy',
            'publicRead', json(CASE WHEN read_policy = 'public' THEN 'true' ELSE 'false' END),
            'publicWrite', json(CASE WHEN write_policy = 'public' THEN 'true' ELSE 'false' END),
            'publishPolicy', json('false'),
            'publishMembers', json('false')),
        -- `allowedApps` is present only under allowList: absent means any app.
        CASE WHEN app_access = 'allowList' THEN json_object('allowedApps', json(CASE
            WHEN json_valid(app_allowed) AND json_type(app_allowed) = 'array' THEN app_allowed
            ELSE '[]'
        END)) ELSE '{}' END)
    END
WHERE read_policy IS NOT NULL;

DELETE FROM space_members WHERE space_uri IN (
    SELECT uri FROM spaces WHERE json_extract(policy, '$."$type"') = 'com.atproto.managedspace.policy'
);

ALTER TABLE spaces DROP COLUMN read_policy;
ALTER TABLE spaces DROP COLUMN managing_app;
ALTER TABLE spaces DROP COLUMN write_policy;
ALTER TABLE spaces DROP COLUMN write_managing_app;
ALTER TABLE spaces DROP COLUMN app_access;
ALTER TABLE spaces DROP COLUMN app_allowed;

ALTER TABLE spaces ADD COLUMN policy_type TEXT
    GENERATED ALWAYS AS (json_extract(policy, '$."$type"')) VIRTUAL;
