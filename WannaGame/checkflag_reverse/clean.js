function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function byteArrayToBase64(byteArray) {
    let result = '';
    for (let i = 0; i < byteArray.length; i++) {
        result += String.fromCharCode(byteArray[i]);
    }
    return btoa(result);
}

function xorStrings(str1, str2) {
    let result = '';
    for (let i = 0; i < str1.length && i < str2.length; i++) {
        const charCode1 = str1.charCodeAt(i);
        const charCode2 = str2.charCodeAt(i);
        const xorResult = charCode1 ^ charCode2;
        result += String.fromCharCode(xorResult);
    }
    return result;
}

function check(flag) {
    const lookupTable = [/* ... an array with elements ... */];
    
    if (flag.length !== 0x2c) {
        return alert('Incorrect length!');
    }

    const byteArray = [];
    for (let i = 0; i < flag.length; i++) {
        byteArray.push(flag.charCodeAt(i));
    }

    for (let round = 0; round < 0x10; round++) {
        for (let i = 0; i < flag.length; i++) {
            byteArray[i] = lookupTable[byteArray[i]];
        }
    }
    
    const base64Result = byteArrayToBase64(byteArray);
    console.log(base64Result);
    
    if (base64Result !== '/52NXNAD7Lui+5G7idT7Dbue0L7vkV/bDey779tzuwf7c5G7c5HbDZHswUs=') {
        return alert('Incorrect flag!');
    }
    
    return alert('Good job, you\'re welcome!!');
}
