using Domain.Interfaces;
using DigitalSignature;
using RSA;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddSingleton<RSACryptor>();
builder.Services.AddSingleton<ICryptor, RSACryptor>();
builder.Services.AddSingleton<IHash, SHA256>();
builder.Services.AddSingleton<DSA>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
