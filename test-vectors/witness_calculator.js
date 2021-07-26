/* globals WebAssembly */
/*

Copyright 2020 0KIMS association.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

const bigInt = require("big-integer");

const fnv = require("fnv-plus");

function flatArray(a) {
    var res = [];
    fillArray(res, a);
    return res;

    function fillArray(res, a) {
        if (Array.isArray(a)) {
            for (let i=0; i<a.length; i++) {
                fillArray(res, a[i]);
            }
        } else {
            res.push(bigInt(a));
        }
    }
}

function fnvHash(str) {
    return fnv.hash(str, 64).hex();
}


module.exports = async function builder(code, options) {

    options = options || {};

    const memory = new WebAssembly.Memory({initial:20000});
    const wasmModule = await WebAssembly.compile(code);

    let wc;

    const instance = await WebAssembly.instantiate(wasmModule, {
        env: {
            "memory": memory
        },
        runtime: {
            error: function(code, pstr, a,b,c,d) {
                let errStr;
                if (code == 7) {
                    errStr=p2str(pstr) + " " + wc.getFr(b).toString() + " != " + wc.getFr(c).toString() + " " +p2str(d);
                } else {
                    errStr=p2str(pstr)+ " " + a + " " + b + " " + c + " " + d;
                }
                console.log("ERROR: ", code, errStr);
                throw new Error(errStr);
            },
            log: function(a) {
                console.log(wc.getFr(a).toString());
            },
            logGetSignal: function(signal, pVal) {
                if (options.logGetSignal) {
                    options.logGetSignal(signal, wc.getFr(pVal) );
                }
            },
            logSetSignal: function(signal, pVal) {
                if (options.logSetSignal) {
                    options.logSetSignal(signal, wc.getFr(pVal) );
                }
            },
            logStartComponent: function(cIdx) {
                if (options.logStartComponent) {
                    options.logStartComponent(cIdx);
                }
            },
            logFinishComponent: function(cIdx) {
                if (options.logFinishComponent) {
                    options.logFinishComponent(cIdx);
                }
            }
        }
    });

    const sanityCheck =
        options &&
        (
            options.sanityCheck ||
            options.logGetSignal ||
            options.logSetSignal ||
            options.logStartComponent ||
            options.logFinishComponent
        );

    wc = new WitnessCalculator(memory, instance, sanityCheck);
    return wc;

    function p2str(p) {
        const i8 = new Uint8Array(memory.buffer);

        const bytes = [];

        for (let i=0; i8[p+i]>0; i++)  bytes.push(i8[p+i]);

        return String.fromCharCode.apply(null, bytes);
    }
};

class WitnessCalculator {
    constructor(memory, instance, sanityCheck) {
        this.memory = memory;
        this.i32 = new Uint32Array(memory.buffer);
        this.instance = instance;

        this.n32 = (this.instance.exports.getFrLen() >> 2) - 2;
        const pRawPrime = this.instance.exports.getPRawPrime();
        console.log("pRawPrime:", pRawPrime);

        // console.log("0:", this.i32[(pRawPrime >> 2)]);
        this.prime = bigInt(0);
        for (let i=this.n32-1; i>=0; i--) {
            this.prime = this.prime.shiftLeft(32);
            this.prime = this.prime.add(bigInt(this.i32[(pRawPrime >> 2) + i]));
        }
        console.log("prime:", this.prime);

        this.mask32 = bigInt("FFFFFFFF", 16);
        console.log("mask32:", this.mask32);
        this.NVars = this.instance.exports.getNVars();
        console.log("NVars:", this.NVars);
        this.n64 = Math.floor((this.prime.bitLength() - 1) / 64)+1;
        console.log("n64:", this.n64);
        this.R = bigInt.one.shiftLeft(this.n64*64);
        console.log("R:", this.R);
        this.RInv = this.R.modInv(this.prime);
        console.log("RInv:", this.RInv);
        this.sanityCheck = sanityCheck;

    }

    async _doCalculateWitness(input, sanityCheck) {
        this.instance.exports.init((this.sanityCheck || sanityCheck) ? 1 : 0);
        const pSigOffset = this.allocInt();
        console.log("pSigOffset:", pSigOffset);
        const pFr = this.allocFr();
        console.log("pFr:", pFr);
        for (let k in input) {
            const h = fnvHash(k);
            const hMSB = parseInt(h.slice(0,8), 16);
            const hLSB = parseInt(h.slice(8,16), 16);
            console.log("h(", k, ") =", h, " = ", hMSB, hLSB);
            this.instance.exports.getSignalOffset32(pSigOffset, 0, hMSB, hLSB);
            const sigOffset = this.getInt(pSigOffset);
            console.log("sigOffset:", sigOffset);
            const fArr = flatArray(input[k]);
            for (let i=0; i<fArr.length; i++) {
                this.setFr(pFr, fArr[i]);
                this.instance.exports.setSignal(0, 0, sigOffset + i, pFr);
            }
        }

    }

    async calculateWitness(input, sanityCheck) {
        const self = this;

        const old0 = self.i32[0];
        const w = [];

        await self._doCalculateWitness(input, sanityCheck);

        for (let i=0; i<self.NVars; i++) {
            const pWitness = self.instance.exports.getPWitness(i);
            w.push(self.getFr(pWitness));
        }

        self.i32[0] = old0;
        return w;
    }

    async calculateBinWitness(input, sanityCheck) {
        const self = this;

        const old0 = self.i32[0];

        await self._doCalculateWitness(input, sanityCheck);

        const pWitnessBuffer = self.instance.exports.getWitnessBuffer();

        self.i32[0] = old0;

        const buff = self.memory.buffer.slice(pWitnessBuffer, pWitnessBuffer + (self.NVars * self.n64 * 8));
        return buff;
    }

    allocInt() {
        const p = this.i32[0];
        this.i32[0] = p+8;
        return p;
    }

    allocFr() {
        const p = this.i32[0];
        this.i32[0] = p+this.n32*4 + 8;
        return p;
    }

    getInt(p) {
        return this.i32[p>>2];
    }

    setInt(p, v) {
        this.i32[p>>2] = v;
    }

    getFr(p) {
        const self = this;
        const idx = (p>>2);

        if (self.i32[idx + 1] & 0x80000000) {
            let res= bigInt(0);
            for (let i=self.n32-1; i>=0; i--) {
                res = res.shiftLeft(32);
                res = res.add(bigInt(self.i32[idx+2+i]));
            }
            if (self.i32[idx + 1] & 0x40000000) {
                return fromMontgomery(res);
            } else {
                return res;
            }

        } else {
            if (self.i32[idx] & 0x80000000) {
                return self.prime.add( bigInt(self.i32[idx]).minus(bigInt(0x100000000)) );
            } else {
                return bigInt(self.i32[idx]);
            }
        }

        function fromMontgomery(n) {
            return n.times(self.RInv).mod(self.prime);
        }

    }


    setFr(p, v) {
        const self = this;
        v = bigInt(v);

        if (v.lt(bigInt("80000000", 16)) ) {
            return setShortPositive(v);
        }
        if (v.geq(self.prime.minus(bigInt("80000000", 16))) ) {
            return setShortNegative(v);
        }
        return setLongNormal(v);

        function setShortPositive(a) {
            self.i32[(p >> 2)] = parseInt(a);
            self.i32[(p >> 2) + 1] = 0;
        }

        function setShortNegative(a) {
            const b = bigInt("80000000", 16 ).add(a.minus(  self.prime.minus(bigInt("80000000", 16 ))));
            self.i32[(p >> 2)] = parseInt(b);
            self.i32[(p >> 2) + 1] = 0;
        }

        function setLongNormal(a) {
            self.i32[(p >> 2)] = 0;
            self.i32[(p >> 2) + 1] = 0x80000000;
            for (let i=0; i<self.n32; i++) {
                self.i32[(p >> 2) + 2 + i] = a.shiftRight(i*32).and(self.mask32);
            }
            console.log(">>>", self.i32[(p >> 2)] , self.i32[(p >> 2) + 1]);
            console.log(">>>", self.i32.slice((p >> 2) + 2, (p >> 2) + 2 + self.n32));
        }
    }
}
