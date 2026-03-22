function permute(input, table) { return table.map(pos => input[pos - 1]).join(''); }
function leftShift(input, shifts) { return input.slice(shifts) + input.slice(0, shifts); }
function xor(a, b) {
    let res = '';
    for (let i = 0; i < a.length; i++) res += a[i] === b[i] ? '0' : '1';
    return res;
}
const S0 = [ [1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 1] ];
const S1 = [ [1, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3] ];
function sBox(input, matrix) {
    const row = parseInt(input[0] + input[3], 2);
    const col = parseInt(input[1] + input[2], 2);
    return matrix[row][col].toString(2).padStart(2, '0');
}
module.exports = function encryptSDES(textBlock, key, mode = 'encrypt') {
    const logs = { original: textBlock, key: key, mode: mode };
    const P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6];
    const P8 = [6, 3, 7, 4, 8, 5, 10, 9];
    const IP = [2, 6, 3, 1, 4, 8, 5, 7];
    const IP_INV = [4, 1, 3, 5, 7, 2, 8, 6];
    const EP = [4, 1, 2, 3, 2, 3, 4, 1];
    const P4 = [2, 4, 3, 1];
    logs.keyGen = {};
    let p10Key = permute(key, P10);
    logs.keyGen.p10 = p10Key;
    let L5 = p10Key.slice(0, 5), R5 = p10Key.slice(5);
    logs.keyGen.split1 = { L5, R5 };
    let L5_shift1 = leftShift(L5, 1), R5_shift1 = leftShift(R5, 1);
    logs.keyGen.shift1 = { L5: L5_shift1, R5: R5_shift1 };
    const K1 = permute(L5_shift1 + R5_shift1, P8);
    logs.K1 = K1;
    let L5_shift2 = leftShift(L5_shift1, 2), R5_shift2 = leftShift(R5_shift1, 2);
    logs.keyGen.shift2 = { L5: L5_shift2, R5: R5_shift2 };
    const K2 = permute(L5_shift2 + R5_shift2, P8);
    logs.K2 = K2;
    function fK(bits8, subkey) {
        let L = bits8.slice(0, 4), R = bits8.slice(4);
        let epR = permute(R, EP);
        let xored = xor(epR, subkey);
        let s0In = xored.slice(0, 4);
        let s1In = xored.slice(4);
        let s0Res = sBox(s0In, S0);
        let s1Res = sBox(s1In, S1);
        let p4Res = permute(s0Res + s1Res, P4);
        let newL = xor(L, p4Res);
        return {
            result: newL + R,
            details: { L, R, epR, subkey, xored, s0In, s1In, s0Res, s1Res, p4Res, newL }
        };
    }
    const round1Key = (mode === 'decrypt') ? K2 : K1;
    const round2Key = (mode === 'decrypt') ? K1 : K2;
    let current = permute(textBlock, IP);
    logs.IP = { before: textBlock, after: current };
    let round1 = fK(current, round1Key);
    current = round1.result;
    logs.FK1 = { keyUsed: round1Key, details: round1.details, result: current };
    let beforeSW = current;
    current = current.slice(4) + current.slice(0, 4);
    logs.SW = { before: beforeSW, after: current };
    let round2 = fK(current, round2Key);
    current = round2.result;
    logs.FK2 = { keyUsed: round2Key, details: round2.details, result: current };
    let beforeIP_INV = current;
    logs.final = permute(current, IP_INV);
    logs.IP_INV = { before: beforeIP_INV, after: logs.final };
    return logs;
};