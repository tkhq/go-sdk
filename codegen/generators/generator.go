package generators

import (
	"encoding/json"
)

// authProxyOnlyPrefix is used internally to disambiguate auth-proxy versions of
// definitions that share a name with a public spec definition but differ in shape
// (e.g. v1InitOtpRequest is an activity envelope publicly but a flat proxy request
// in the auth proxy spec).
const authProxyOnlyPrefix = "__authProxyOnly__"

// externalSignerOnlyPrefix is the equivalent internal disambiguation prefix for the
// external-signer spec.
const externalSignerOnlyPrefix = "__externalSignerOnly__"

type generator struct {
	specs                  []*swaggerSpec
	definitions            map[string]*schema
	defNamePrefix          map[string]string // raw definition key → Go name prefix ("AuthProxy", "ExternalSigner")
	authProxyRefRemap      map[string]string // original ref name → remapped key (for divergent shared defs)
	externalSignerRefRemap map[string]string
	nameByRef              map[string]string
	rawByGoName            map[string]string // reverse of nameByRef: Go exported name → swagger raw key
	usedNames              map[string]string
	operations             []operationInfo
	activitiesConfig       *activitiesConfig
	allVersions            bool
}

type operationInfo struct {
	Path          string
	OperationName string
	MethodName    string
	MethodType    string
	ActivityType  string
	RequestDef    string
	ResponseDef   string
	IntentDef     string
	ResultDef     string
	Description   string
	Deprecated    bool
}

const (
	methodTypeActivityDecision = "activityDecision"
	methodTypeCommand          = "command"
	methodTypeProxy            = "proxy"
	methodTypeQuery            = "query"
	goTypeAny                  = "any"
	goTypeMapStringAny         = "map[string]any"
	goTypeString               = "string"
)

func newGenerator(specs []*swaggerSpec, cfg *activitiesConfig, allVersions bool) *generator {
	g := &generator{
		specs:                  specs,
		definitions:            map[string]*schema{},
		defNamePrefix:          map[string]string{},
		authProxyRefRemap:      map[string]string{},
		externalSignerRefRemap: map[string]string{},
		nameByRef:              map[string]string{},
		rawByGoName:            map[string]string{},
		usedNames:              map[string]string{},
		activitiesConfig:       cfg,
		allVersions:            allVersions,
	}
	// Load public spec first; it wins for identically-shaped shared definitions.
	for name, def := range specs[0].Definitions {
		g.definitions[name] = def
	}

	// auth proxy spec
	g.authProxyRefRemap = g.mergeSecondarySpec(specs[1], "AuthProxy", authProxyOnlyPrefix, true)

	// protoc-gen-openapiv2 names a message by its short name when that is unique
	// within the generated file set and by its fully-qualified name otherwise, so
	// the same proto message can surface under different definition names in
	// different specs (e.g. v1PayloadEncoding vs immutablecommonv1PayloadEncoding).
	// Canonicalize those aliases onto the public names before merging so shared
	// definitions compare equal instead of spawning duplicate types.
	// external signer spec
	canonicalizeAliasedDefs(specs[2], specs[0])
	g.externalSignerRefRemap = g.mergeSecondarySpec(specs[2], "ExternalSigner", externalSignerOnlyPrefix, false)

	g.buildNameMap()

	return g
}

// mergeSecondarySpec merges a non-public spec's definitions into the generator.
// Definitions identical to a same-named public one are dropped in favor of the public
// def; divergent same-named ones are stored under internalKeyPrefix and reported in
// the returned ref-remap; spec-only definitions are stored as-is, Go-name-prefixed
// with goNamePrefix only when prefixNewDefs is set.
func (g *generator) mergeSecondarySpec(spec *swaggerSpec, goNamePrefix string, internalKeyPrefix string, prefixNewDefs bool) map[string]string {
	refRemap := map[string]string{}

	for name, def := range spec.Definitions {
		pubDef, sharedWithPublic := g.specs[0].Definitions[name]
		switch {
		case !sharedWithPublic:
			g.definitions[name] = def
			if prefixNewDefs {
				g.defNamePrefix[name] = goNamePrefix
			}
		case schemasEqual(pubDef, def):
			// Identical shape across specs — public def already stored, no prefix needed.
		default:
			// Divergent: store this spec's version under a separate internal key.
			remapped := internalKeyPrefix + name
			g.definitions[remapped] = def
			g.defNamePrefix[remapped] = goNamePrefix
			refRemap[name] = remapped
		}
	}

	return refRemap
}

// canonicalizeAliasedDefs finds definitions in spec that do not exist under the same
// name in the base spec but are byte-identical to exactly one base definition, then
// renames them (dropping the duplicate and rewriting every $ref) onto the base name.
// Runs to a fixpoint so definitions that only differ through such refs collapse too.
func canonicalizeAliasedDefs(spec *swaggerSpec, base *swaggerSpec) {
	for {
		renames := map[string]string{}

		for _, name := range sortedKeys(spec.Definitions) {
			if _, inBase := base.Definitions[name]; inBase {
				continue
			}

			target := ""
			for _, baseName := range sortedKeys(base.Definitions) {
				if !schemasEqual(spec.Definitions[name], base.Definitions[baseName]) {
					continue
				}

				if target != "" {
					// Ambiguous shape match — leave the definition alone.
					target = ""
					break
				}

				target = baseName
			}

			if target != "" {
				renames[name] = target
			}
		}

		if len(renames) == 0 {
			return
		}

		for name := range renames {
			delete(spec.Definitions, name)
		}

		rewriteSpecRefs(spec, renames)
	}
}

func rewriteSpecRefs(spec *swaggerSpec, renames map[string]string) {
	for _, def := range spec.Definitions {
		rewriteSchemaRefs(def, renames)
	}

	for _, item := range spec.Paths {
		if item.Post == nil {
			continue
		}

		for _, param := range item.Post.Parameters {
			rewriteSchemaRefs(param.Schema, renames)
		}

		for _, resp := range item.Post.Responses {
			rewriteSchemaRefs(resp.Schema, renames)
		}
	}
}

func rewriteSchemaRefs(s *schema, renames map[string]string) {
	if s == nil {
		return
	}

	if s.Ref != "" {
		if target, ok := renames[refName(s.Ref)]; ok {
			s.Ref = "#/definitions/" + target
		}
	}

	rewriteSchemaRefs(s.Items, renames)

	for _, prop := range s.Properties {
		rewriteSchemaRefs(prop, renames)
	}
}

func schemasEqual(a, b *schema) bool {
	if a == nil || b == nil {
		return a == b
	}

	aJSON, err := json.Marshal(a)
	if err != nil {
		return false
	}

	bJSON, err := json.Marshal(b)
	if err != nil {
		return false
	}

	return string(aJSON) == string(bJSON)
}
