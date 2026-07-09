package generators

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func (g *generator) remapAuthProxyRef(authProxy bool, ref string) string {
	if !authProxy || ref == "" {
		return ref
	}

	if remapped, ok := g.authProxyRefRemap[ref]; ok {
		return remapped
	}

	return ref
}

var activityWireBodyRE = regexp.MustCompile(`Request(V\d+)?$`)

const typeObject = "object"

//nolint:gocyclo // name-deduplication logic requires tracking several concurrent states
func (g *generator) buildNameMap() {
	names := sortedKeys(g.definitions)
	for _, raw := range names {
		nameSource := strings.TrimPrefix(raw, authProxyOnlyPrefix)

		base := exportedName(stripLeadingVersion(normalizeProtoPackagePrefixes(nameSource)))
		if base == "" {
			continue
		}

		if g.authProxyDefs[raw] {
			base = "AuthProxy" + base
		}
		// Activity wire envelopes (type + timestampMs + organizationId + parameters)
		// get a Body suffix so they don't collide with the sugared XxxRequest
		// method-input types emitted by writeActivityInput.
		if isActivityWireBody(g.definitions[raw]) {
			base = activityWireBodyRE.ReplaceAllString(base, "Body$1")
		}

		name := base
		if owner, exists := g.usedNames[name]; exists && owner != raw {
			name = exportedName(stripLeadingVersion(nameSource))
			if g.authProxyDefs[raw] {
				name = "AuthProxy" + name
			}

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

func (g *generator) extractLatestActivityTypes() map[string]string {
	latest := map[string]string{}
	latestVersion := map[string]int{}
	g.collectActivityTypesFromIntentDefinitions(latest, latestVersion)

	for _, def := range g.definitions {
		walkSchemaStrings(def, func(value string) {
			if !strings.HasPrefix(value, "ACTIVITY_TYPE_") {
				return
			}

			setLatestActivityType(latest, latestVersion, value)
		})
	}

	return latest
}

func (g *generator) collectActivityTypesFromIntentDefinitions(latest map[string]string, latestVersion map[string]int) {
	re := regexp.MustCompile(`^v[0-9]+([A-Z][A-Za-z0-9]*?)Intent(V([0-9]+))?$`)
	for raw := range g.definitions {
		match := re.FindStringSubmatch(raw)
		if match == nil {
			continue
		}

		version := 1

		if match[3] != "" {
			parsed, err := strconv.Atoi(match[3])
			if err == nil {
				version = parsed
			}
		}

		base := "ACTIVITY_TYPE_" + upperSnake(match[1])

		activityType := base
		if version > 1 {
			activityType = fmt.Sprintf("%s_V%d", base, version)
		}

		setLatestActivityType(latest, latestVersion, activityType)
	}
}

func setLatestActivityType(latest map[string]string, latestVersion map[string]int, activityType string) {
	base := stripActivityVersion(activityType)

	version := activityTypeVersion(activityType)
	if existing, ok := latestVersion[base]; !ok || version >= existing {
		latestVersion[base] = version
		latest[base] = activityType
	}
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

	for _, spec := range g.specs {
		for _, path := range sortedKeys(spec.Paths) {
			item := spec.Paths[path]
			if item.Post == nil {
				continue
			}

			op := item.Post
			operationName := strings.TrimPrefix(op.OperationID, "PublicApiService_")

			operationName = strings.TrimPrefix(operationName, "AuthProxyService_")
			if operationName == "" || strings.Contains(operationName, "NOOP") {
				continue
			}

			authProxy := strings.HasPrefix(op.OperationID, "AuthProxyService_")
			requestDef := g.remapAuthProxyRef(authProxy, requestDefinition(op))
			responseDef := g.remapAuthProxyRef(authProxy, responseDefinition(op))
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
			// the current method is named e.g. CreateUsersV4 instead of CreateUsers.
			if g.allVersions && (methodType == methodTypeCommand || methodType == methodTypeActivityDecision) && !authProxy {
				methodName += activityVersionSuffix(activityType)
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

	activityType := baseActivityType
	if typeProp := req.Properties["type"]; typeProp != nil && len(typeProp.Enum) > 0 {
		activityType = typeProp.Enum[0]
	}

	if latestActivityType, ok := g.activityTypeByBase[stripActivityVersion(activityType)]; ok {
		return latestActivityType
	}

	return activityType
}

func activityTypeVersion(value string) int {
	match := activityVersionGroupRE.FindStringSubmatch(value)
	if match == nil {
		return 1
	}

	version, err := strconv.Atoi(match[1])
	if err != nil {
		return 1
	}

	return version
}

func walkSchemaStrings(s *schema, visit func(string)) {
	if s == nil {
		return
	}

	for _, value := range s.Enum {
		visit(value)
	}

	for _, prop := range s.Properties {
		walkSchemaStrings(prop, visit)
	}

	walkSchemaStrings(s.Items, visit)
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
