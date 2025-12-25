const btnEL = document.querySelector(".btn")
const inputEL = document.getElementById("input")
const copyEL = document.querySelector(".fa-2x")
const alertEL = document.querySelector(".alert")

copyEL.addEventListener("click", ()=>{
    copypass();
})
btnEL.addEventListener("click", ()=>{
    createpass();
})
copyEL.addEventListener("click", ()=>{
    alertEL.classList.remove("active")
    setTimeout(() =>{
        alertEL.classList.add("active");
    }, 2000);

});

function createpass(){
    const chars= 
    "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~!@#$%^&*()_+<>?,.{}[]<>()_-;:`"
    const plength= 8;
    let passwd="";
    for (let index = 0; index < plength; index++) {
        const ran= Math.floor(Math.random() *chars.length)
        passwd += chars.substring(ran, ran+1 );
        
    }
    inputEL.value = passwd;
    alertEL.innerText = "Copied Successfully !";
}

function copypass(){
    //inputEL.select();
    navigator.clipboard.writeText(inputEL.value);
}