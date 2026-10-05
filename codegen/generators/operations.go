package generators

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

func remapSecondaryRef(remap map[string]string, ref string) string {
	if remapped, ok := remap[ref]; ok {
		return remapped
	}

	return ref
}

var activityWireBodyRE = regexp.MustCompile(`Request(V\d+)?$`)

const typeObject = "object"

func (g *generator) buildNameMap() {
	names := sortedKeys(g.definitions)
	for _, raw := range names {
		nameSource := strings.TrimPrefix(raw, authProxyOnlyPrefix)
		nameSource = strings.TrimPrefix(nameSource, externalSignerOnlyPrefix)

		base := exportedName(stripLeadingVersion(normalizeProtoPackagePrefixes(nameSource)))
		if base == "" {
			continue
		}

		base = g.defNamePrefix[raw] + base
		// Activity wire envelopes (type + timestampMs + organizationId + parameters)
		// get a Body suffix so they don't collide with the sugared XxxRequest
		// method-input types emitted by writeActivityInput.
		if isActivityWireBody(g.definitions[raw]) {
			base = activityWireBodyRE.ReplaceAllString(base, "Body$1")
		}

		name := base
		if owner, exists := g.usedNames[name]; exists && owner != raw {
			name = g.defNamePrefix[raw] + exportedName(stripLeadingVersion(nameSource))

			for i := 2; ; i++ {
				if _, taken := g.usedNames[name]; !taken {
					break
				}

				name = fmt.Sprintf("%s%d", base, i)
			}
		}

		g.usedNames[name] = raw

		g.nameByRef[raw] = name
		if _, exists := g.rawByGoName[name]; !exists {
			g.rawByGoName[name] = raw
		}
	}
}

func isActivityWireBody(def *schema) bool {
	if def == nil || def.Type != typeObject {
		return false
	}

	for _, key := range [...]string{"type", "timestampMs", "organizationId", "parameters"} {
		if _, ok := def.Properties[key]; !ok {
			return false
		}
	}

	return true
}

//nolint:gocyclo,cyclop // operation collection requires handling many endpoint shape variants
func (g *generator) collectOperations() {
	var operations []operationInfo

	// baseActivityType → endpoint metadata, used in --all mode to emit historical methods.
	type endpointMeta struct {
		path   string
		method string
		opName string
	}

	baseToEndpoint := map[string]endpointMeta{}
	// Activity types emitted from swagger endpoints (current versions).
	currentActivityTypes := map[string]bool{}

	for specIndex, spec := range g.specs {
		// Operation-level refs from a secondary spec must resolve to that spec's
		// internally-remapped keys for definitions that diverge from the public spec.
		refRemap := map[string]string{}

		switch specIndex {
		case 1:
			refRemap = g.authProxyRefRemap
		case 2:
			refRemap = g.externalSignerRefRemap
		}

		for _, path := range sortedKeys(spec.Paths) {
			item := spec.Paths[path]
			if item.Post == nil {
				continue
			}

			op := item.Post
			operationName := strings.TrimPrefix(op.OperationID, "PublicApiService_")

			operationName = strings.TrimPrefix(operationName, "AuthProxyService_")
			operationName = strings.TrimPrefix(operationName, "ExternalSignerApiService_")
			if operationName == "" || strings.Contains(operationName, "NOOP") {
				continue
			}

			authProxy := strings.HasPrefix(op.OperationID, "AuthProxyService_")
			requestDef := remapSecondaryRef(refRemap, requestDefinition(op))
			responseDef := remapSecondaryRef(refRemap, responseDefinition(op))
			methodType := g.methodType(op, path, responseDef)
			activityType := g.activityType(operationName, requestDef)
			// activities.json is the authoritative source for intent/result types.
			var intentDef, resultDef string

			if entry, ok := g.activitiesConfig.Activities[activityType]; ok {
				if entry.Internal {
					continue
				}

				intentDef = g.resolveDefinitionName(entry.IntentType)
				resultDef = g.resolveDefinitionName(entry.ResultType)
			}

			methodName := g.goName(operationName)
			if authProxy {
				methodName = "AuthProxy" + methodName
			}

			// In --all mode, append the version suffix derived from the activity type so that
			// the current method is named e.g. CreateUsersV4 / SolSendTransactionV2 instead of
			// CreateUsers / SolSendTransaction. Skip when the operation name already ends with
			// that suffix so we do not emit doubled names like CreateUsersV4V4.
			if g.allVersions && (methodType == methodTypeCommand || methodType == methodTypeActivityDecision) && !authProxy {
				if suffix := activityVersionSuffix(activityType); suffix != "" && !strings.HasSuffix(methodName, suffix) {
					methodName += suffix
				}
			}

			operations = append(operations, operationInfo{
				Path:          path,
				OperationName: operationName,
				MethodName:    methodName,
				MethodType:    methodType,
				ActivityType:  activityType,
				RequestDef:    requestDef,
				ResponseDef:   responseDef,
				IntentDef:     intentDef,
				ResultDef:     resultDef,
				Description:   firstNonEmpty(op.Description, op.Summary),
				Deprecated:    op.Deprecated,
			})

			// Track base activity type → endpoint for --all historical generation.
			if methodType == methodTypeCommand && !authProxy {
				currentActivityTypes[activityType] = true

				base := stripActivityVersion(activityType)
				if _, exists := baseToEndpoint[base]; !exists {
					baseToEndpoint[base] = endpointMeta{
						path:   path,
						method: g.goName(operationName),
						opName: operationName,
					}
				}
			}
		}
	}

	// In --all mode, emit one method per historical config entry (entries whose activity
	// type is not the current swagger version but shares a base with a known endpoint).
	if g.allVersions {
		for _, actType := range sortedKeys(g.activitiesConfig.Activities) {
			if currentActivityTypes[actType] {
				continue
			}

			if g.activitiesConfig.Activities[actType].Internal {
				continue
			}

			base := stripActivityVersion(actType)

			meta, ok := baseToEndpoint[base]
			if !ok {
				continue
			}

			entry := g.activitiesConfig.Activities[actType]
			intentDef := g.resolveDefinitionName(entry.IntentType)
			resultDef := g.resolveDefinitionName(entry.ResultType)
			suffix := activityVersionSuffix(actType)
			operations = append(operations, operationInfo{
				Path:          meta.path,
				OperationName: meta.opName,
				MethodName:    meta.method + suffix,
				MethodType:    methodTypeCommand,
				ActivityType:  actType,
				IntentDef:     intentDef,
				ResultDef:     resultDef,
			})
		}
	}

	sort.SliceStable(operations, func(i, j int) bool {
		return operations[i].MethodName < operations[j].MethodName
	})
	g.operations = operations
}

func requestDefinition(op *operation) string {
	if op == nil {
		return ""
	}

	for _, param := range op.Parameters {
		if param.In == "body" && param.Schema != nil && param.Schema.Ref != "" {
			return refName(param.Schema.Ref)
		}
	}

	return ""
}

func responseDefinition(op *operation) string {
	if op == nil {
		return ""
	}

	for _, code := range []string{"200", "201", "default"} {
		resp, ok := op.Responses[code]
		if !ok || resp.Schema == nil || resp.Schema.Ref == "" {
			continue
		}

		return refName(resp.Schema.Ref)
	}

	return ""
}

func (g *generator) activityType(operationName string, requestDef string) string {
	baseActivityType := activityTypeFromOperation(operationName)

	req := g.definitions[requestDef]
	if req == nil {
		return baseActivityType
	}

	// Prefer the request wire enum when present so shared endpoints such as
	// eth_send_transaction / sol_send_transaction document the current activity
	// version (e.g. ACTIVITY_TYPE_SOL_SEND_TRANSACTION_V2) while --all mode still
	// remaps historical activity types onto the same path.
	if typeProp := req.Properties["type"]; typeProp != nil && len(typeProp.Enum) > 0 {
		return typeProp.Enum[0]
	}

	return baseActivityType
}

func (g *generator) methodType(op *operation, path string, responseDef string) string {
	if op != nil && strings.HasPrefix(op.OperationID, "AuthProxyService_") {
		return methodTypeProxy
	}

	if strings.Contains(path, "/submit/") && (responseDef == "v1ActivityResponse" || responseDef == "ActivityResponse") {
		switch {
		case strings.Contains(path, "approve_activity"), strings.Contains(path, "reject_activity"):
			return methodTypeActivityDecision
		default:
			return methodTypeCommand
		}
	}

	return methodTypeQuery
}
