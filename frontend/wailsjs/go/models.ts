export namespace main {
	
	export class Check {
	    name: string;
	    status: string;
	    statusText: string;
	    detail: string;
	
	    static createFrom(source: any = {}) {
	        return new Check(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.status = source["status"];
	        this.statusText = source["statusText"];
	        this.detail = source["detail"];
	    }
	}
	export class Fact {
	    label: string;
	    value: string;
	    tone: string;
	
	    static createFrom(source: any = {}) {
	        return new Fact(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.value = source["value"];
	        this.tone = source["tone"];
	    }
	}
	export class HwItem {
	    label: string;
	    value: string;
	
	    static createFrom(source: any = {}) {
	        return new HwItem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.value = source["value"];
	    }
	}
	export class HwGroup {
	    title: string;
	    items: HwItem[];
	
	    static createFrom(source: any = {}) {
	        return new HwGroup(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.title = source["title"];
	        this.items = this.convertValues(source["items"], HwItem);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class Indicator {
	    severity: string;
	    text: string;
	
	    static createFrom(source: any = {}) {
	        return new Indicator(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.severity = source["severity"];
	        this.text = source["text"];
	    }
	}
	export class KeyInfo {
	    label: string;
	    value: string;
	    note: string;
	    tone: string;
	
	    static createFrom(source: any = {}) {
	        return new KeyInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.value = source["value"];
	        this.note = source["note"];
	        this.tone = source["tone"];
	    }
	}
	export class Line {
	    kind: number;
	    text: string;
	    label: string;
	    value: string;
	    muted: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Line(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.kind = source["kind"];
	        this.text = source["text"];
	        this.label = source["label"];
	        this.value = source["value"];
	        this.muted = source["muted"];
	    }
	}
	export class Recommendation {
	    title: string;
	    text: string;
	
	    static createFrom(source: any = {}) {
	        return new Recommendation(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.title = source["title"];
	        this.text = source["text"];
	    }
	}
	export class RunOpts {
	    showFullKey: boolean;
	    dlv: boolean;
	    autoRemove: boolean;
	    restart: boolean;
	    confirm: boolean;
	    key: string;
	    n: number;
	
	    static createFrom(source: any = {}) {
	        return new RunOpts(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.showFullKey = source["showFullKey"];
	        this.dlv = source["dlv"];
	        this.autoRemove = source["autoRemove"];
	        this.restart = source["restart"];
	        this.confirm = source["confirm"];
	        this.key = source["key"];
	        this.n = source["n"];
	    }
	}
	export class Status {
	    admin: boolean;
	    strings: Record<string, string>;
	    restored: Line[];
	
	    static createFrom(source: any = {}) {
	        return new Status(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.admin = source["admin"];
	        this.strings = source["strings"];
	        this.restored = this.convertValues(source["restored"], Line);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Verdict {
	    level: string;
	    title: string;
	    summary: string;
	    typeLabel: string;
	    typeValue: string;
	    count: number;
	    facts: Fact[];
	    hw: HwGroup[];
	    keys: KeyInfo[];
	    rec?: Recommendation;
	    indicators: Indicator[];
	    checks: Check[];
	    lines: Line[];
	    admin: boolean;
	    limits: string;
	
	    static createFrom(source: any = {}) {
	        return new Verdict(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.level = source["level"];
	        this.title = source["title"];
	        this.summary = source["summary"];
	        this.typeLabel = source["typeLabel"];
	        this.typeValue = source["typeValue"];
	        this.count = source["count"];
	        this.facts = this.convertValues(source["facts"], Fact);
	        this.hw = this.convertValues(source["hw"], HwGroup);
	        this.keys = this.convertValues(source["keys"], KeyInfo);
	        this.rec = this.convertValues(source["rec"], Recommendation);
	        this.indicators = this.convertValues(source["indicators"], Indicator);
	        this.checks = this.convertValues(source["checks"], Check);
	        this.lines = this.convertValues(source["lines"], Line);
	        this.admin = source["admin"];
	        this.limits = source["limits"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

