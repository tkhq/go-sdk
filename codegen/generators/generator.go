package generators

import (
	"encoding/json"
)

// authProxyOnlyPrefix is used internally to disambiguate auth-proxy versions of
// definitions that share a name with a public spec definition but differ in shape
// (e.g. v1InitOtpRequest is an activity envelope publicly but a flat proxy request
// in the auth proxy spec).
const authProxyOnlyPrefix = "__authProxyOnly__"

type generator struct {
	specs              []*swaggerSpec
	definitions        map[string]*schema
	authProxyDefs      map[string]bool
	authProxyRefRemap  map[string]string // original ref name → remapped key (for divergent shared defs)
	nameByRef          map[string]string
	rawByGoName        map[string]string // reverse of nameByRef: Go exported name → swagger raw key
	usedNames          map[string]string
	activityTypeByBase map[string]string
	operations         []operationInfo
	activitiesConfig   *activitiesConfig
	allVersions        bool
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
		specs:             specs,
		definitions:       map[string]*schema{},
		authProxyDefs:     map[string]bool{},
		authProxyRefRemap: map[string]string{},
		nameByRef:         map[string]string{},
		rawByGoName:       map[string]string{},
		usedNames:         map[string]string{},
		activitiesConfig:  cfg,
		allVersions:       allVersions,
	}
	// Load public spec first; it wins for identically-shaped shared definitions.
	if len(specs) > 0 {
		for name, def := range specs[0].Definitions {
			g.definitions[name] = def
		}
	}

	if len(specs) > 1 {
		for name, def := range specs[1].Definitions {
			pubDef, sharedWithPublic := specs[0].Definitions[name]
			switch {
			case !sharedWithPublic:
				// Auth-proxy-only: store and prefix with AuthProxy.
				g.definitions[name] = def
				g.authProxyDefs[name] = true
			case schemasEqual(pubDef, def):
				// Identical shape across specs — public def already stored, no prefix needed.
			default:
				// Divergent: store the auth-proxy version under a separate internal key.
				remapped := authProxyOnlyPrefix + name
				g.definitions[remapped] = def
				g.authProxyDefs[remapped] = true
				g.authProxyRefRemap[name] = remapped
			}
		}
	}

	g.activityTypeByBase = g.extractLatestActivityTypes()
	g.buildNameMap()

	return g
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
