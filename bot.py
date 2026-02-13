import discord
from discord.ext import commands, tasks
from discord.ui import View, Button
import random
import string
import hashlib
import time
import json
import os
import asyncio
import threading
import requests
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
import base64
from cryptography.fernet import Fernet

# Flask imports
from flask import Flask, request, render_template, jsonify, abort, send_from_directory, make_response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ============== CONFIGURATION ==============
def load_config() -> Dict[str, Any]:
    config_path = 'config.json'
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file {config_path} not found!")
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)

CONFIG = load_config()

# Setup logging
os.makedirs('logs', exist_ok=True)
logging.basicConfig(
    level=getattr(logging, CONFIG['logging']['log_level']),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(CONFIG['logging']['log_file'], maxBytes=10*1024*1024, backupCount=5),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('DoubleCounter')

# ============== ENCRYPTION ==============
class EncryptionManager:
    def __init__(self):
        # Generate encryption key from secret
        key_material = CONFIG['web_server']['secret_key'].encode()
        key = base64.urlsafe_b64encode(hashlib.sha256(key_material).digest())
        self.cipher = Fernet(key)
    
    def encrypt_params(self, code: str, user_id: int) -> str:
        """Encrypt code and user_id into single token"""
        data = f"{code}|{user_id}"
        encrypted = self.cipher.encrypt(data.encode())
        # Make URL safe
        return base64.urlsafe_b64encode(encrypted).decode().rstrip('=')
    
    def decrypt_params(self, token: str) -> tuple:
        """Decrypt token to get code and user_id"""
        try:
            # Add padding if needed
            padding = 4 - len(token) % 4
            if padding != 4:
                token += '=' * padding
            
            encrypted = base64.urlsafe_b64decode(token.encode())
            decrypted = self.cipher.decrypt(encrypted).decode()
            code, user_id = decrypted.split('|')
            return code, user_id
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return None, None

encryption_manager = EncryptionManager()

# ============== FLASK APP ==============
app = Flask(__name__, template_folder='web', static_folder='web/static')
app.secret_key = CONFIG['web_server']['secret_key']
CORS(app)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[f"{CONFIG['security']['max_requests_per_minute']} per minute"]
)

# ============== DATA MANAGEMENT ==============
class DataManager:
    def __init__(self):
        self.file = CONFIG['database']['file']
        self.data = self.load()
        self.lock = threading.Lock()
        self.backup_dir = 'backups'
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def load(self) -> Dict:
        if os.path.exists(self.file):
            try:
                with open(self.file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                logger.error("Database corrupted, creating new one")
                return self._default_data()
        return self._default_data()
    
    def _default_data(self) -> Dict:
        return {
            "pending_verifications": {},
            "verified_users": {},
            "blocked_fingerprints": [],
            "blocked_ips": [],
            "attempts": {},
            "logs": [],
            "stats": {
                "total_verifications": 0,
                "blocked_attempts": 0,
                "alt_accounts_detected": 0
            }
        }
    
    def save(self):
        with self.lock:
            temp_file = f"{self.file}.tmp"
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, indent=4, ensure_ascii=False)
            os.replace(temp_file, self.file)
    
    def add_log(self, action: str, user_id: int, details: str, level: str = "info"):
        log_entry = {
            "timestamp": time.time(),
            "action": action,
            "user_id": user_id,
            "details": details,
            "level": level
        }
        self.data['logs'].append(log_entry)
        if len(self.data['logs']) > 1000:
            self.data['logs'] = self.data['logs'][-1000:]
        self.save()
        
        if CONFIG['logging'].get('webhook_url'):
            self._send_webhook(log_entry)
    
    def _send_webhook(self, log_entry: Dict):
        try:
            color = 0x00ff00 if log_entry['level'] == 'info' else 0xff0000 if log_entry['level'] == 'error' else 0xffff00
            embed = {
                "title": f"<:verify:1470970638968553685> {log_entry['action']}",
                "description": log_entry['details'],
                "color": color,
                "timestamp": datetime.fromtimestamp(log_entry['timestamp']).isoformat(),
                "footer": {"text": f"User ID: {log_entry['user_id']}"}
            }
            requests.post(CONFIG['logging']['webhook_url'], json={"embeds": [embed]}, timeout=5)
        except Exception as e:
            logger.error(f"Webhook error: {e}")

data_manager = DataManager()

# ============== SECURITY MANAGER ==============
class SecurityManager:
    @staticmethod
    def generate_code(user_id: int) -> str:
        timestamp = str(int(time.time()))
        random_chars = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        secret = CONFIG['web_server']['secret_key']
        salt = CONFIG['security']['fingerprint_salt']
        unique_string = f"{user_id}{timestamp}{random_chars}{secret}{salt}"
        return hashlib.sha256(unique_string.encode()).hexdigest()[:16]
    
    @staticmethod
    def verify_code(code: str, user_id: int) -> bool:
        pending = data_manager.data['pending_verifications'].get(str(user_id))
        if not pending:
            return False
        return pending['code'] == code and time.time() - pending['timestamp'] < CONFIG['security']['code_expiry_minutes'] * 60
    
    @staticmethod
    def check_account_age(user: discord.Member) -> bool:
        min_age = CONFIG['security']['min_account_age_days']
        if min_age == 0:
            return True
        account_age = (datetime.now(user.created_at.tzinfo or datetime.timezone.utc) - user.created_at).days
        return account_age >= min_age
    
    @staticmethod
    def check_ip_reputation(ip: str) -> Dict[str, Any]:
        result = {"clean": True, "vpn": False, "proxy": False, "threat_score": 0}
        
        if CONFIG['api_keys'].get('vpnapi_io'):
            try:
                response = requests.get(
                    f"https://vpnapi.io/api/{ip}?key={CONFIG['api_keys']['vpnapi_io']}",
                    timeout=5
                )
                data = response.json()
                if data.get('security'):
                    result['vpn'] = data['security'].get('vpn', False)
                    result['proxy'] = data['security'].get('proxy', False)
                    result['tor'] = data['security'].get('tor', False)
                    result['clean'] = not (result['vpn'] or result['proxy'] or result.get('tor'))
            except Exception as e:
                logger.error(f"VPNAPI check failed: {e}")
        
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}?fields=proxy,hosting,query",
                timeout=5
            )
            data = response.json()
            if data.get('proxy') or data.get('hosting'):
                result['proxy'] = True
                result['clean'] = False
        except Exception as e:
            logger.error(f"IP-API check failed: {e}")
        
        return result
    
    @staticmethod
    def verify_captcha(token: str) -> bool:
        if not CONFIG['api_keys'].get('cloudflare_secret'):
            return True  
        
        try:
            response = requests.post(
                'https://challenges.cloudflare.com/turnstile/v0/siteverify',
                data={
                    'secret': CONFIG['api_keys']['cloudflare_secret'],
                    'response': token
                },
                timeout=10
            )
            result = response.json()
            return result.get('success', False)
        except Exception as e:
            logger.error(f"CAPTCHA verification failed: {e}")
            return True  
    
    @staticmethod
    def check_alt_account(user_id: int, fingerprint: str, ip: str) -> Dict[str, Any]:
        if not CONFIG['security']['block_alts']:
            return {"is_alt": False, "reason": None}
        
        data = data_manager.data
        reasons = []
        
        if fingerprint in data.get('blocked_fingerprints', []):
            reasons.append("Blocked fingerprint")
        
        for uid, info in data['verified_users'].items():
            if uid != str(user_id):
                if info.get('fingerprint') == fingerprint:
                    reasons.append(f"Shared fingerprint with user {uid}")
                
                if info.get('ip') == ip:
                    last_verify = info.get('verified_at', 0)
                    if time.time() - last_verify < 86400:
                        reasons.append(f"Shared IP with user {uid} (within 24h)")
        
        return {
            "is_alt": len(reasons) > 0,
            "reason": "; ".join(reasons) if reasons else None
        }

# ============== FLASK ROUTES ==============
def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr

@app.route('/')
def home():
    return jsonify({
        "status": "running",
        "service": "Double Counter Verification",
        "version": "2.1",
        "protection": "active"
    })

@app.route('/verify')
@limiter.limit("10 per minute")
def verify_page():
    token = request.args.get('t')
    
    if not token:
        return abort(400, "Missing token")
    
    code, user_id = encryption_manager.decrypt_params(token)
    
    if not code or not user_id:
        return abort(400, "Invalid token")
    
    pending = data_manager.data['pending_verifications'].get(user_id)
    
    if not pending or pending['code'] != code:
        return abort(400, "Invalid or expired verification")
    
    if time.time() - pending['timestamp'] > CONFIG['security']['code_expiry_minutes'] * 60:
        return abort(400, "Verification link expired")
    
    return render_template('verify.html')

@app.route('/failed.html')
def failed_page():
    return render_template('failed.html')

@app.route('/success.html')
def success_page():
    return render_template('success.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('web/static', filename)

@app.route('/api/check/<token>')
@limiter.limit("20 per minute")
def check_status(token):
    code, user_id = encryption_manager.decrypt_params(token)
    
    if not code or not user_id:
        return jsonify({"found": False})
    
    pending = data_manager.data['pending_verifications'].get(user_id)
    
    if not pending or pending['code'] != code:
        return jsonify({"found": False})
    
    return jsonify({
        "found": True,
        "verified": pending.get('verified', False),
        "username": pending.get('username'),
        "user_id": user_id,
        "avatar_url": pending.get('avatar_url'),
        "server": pending.get('guild_name'),
        "attempts": pending.get('attempts', 0)
    })

@app.route('/api/captcha-required')
@limiter.limit("20 per minute")
def captcha_required():
    """Check if CAPTCHA is required based on config"""
    has_cloudflare_key = bool(CONFIG['api_keys'].get('cloudflare_secret'))
    captcha_enabled = CONFIG['verification'].get('require_captcha', True)
    
    return jsonify({
        "required": has_cloudflare_key and captcha_enabled
    })

@app.route('/api/verify', methods=['POST'])
@limiter.limit("5 per minute")
def api_verify():
    data = request.get_json() or {}
    token = data.get('token')
    fingerprint = data.get('fingerprint', '')
    captcha_token = data.get('captcha_token', '')
    
    if not token:
        return jsonify({"success": False, "error": "Missing token"})
    
    code, user_id = encryption_manager.decrypt_params(token)
    
    if not code or not user_id:
        return jsonify({"success": False, "error": "Invalid token"})
    
    client_ip = get_client_ip()
    
    if client_ip in data_manager.data.get('blocked_ips', []):
        data_manager.add_log("BLOCKED_IP_ATTEMPT", int(user_id), f"IP: {client_ip}", "warning")
        return jsonify({"success": False, "error": "Access denied"})
    
    pending = data_manager.data['pending_verifications'].get(user_id)
    if not pending or pending['code'] != code:
        return jsonify({"success": False, "error": "Invalid verification"})
    
    if pending.get('attempts', 0) >= CONFIG['security']['max_attempts']:
        return jsonify({"success": False, "error": "Too many attempts"})
    
    if CONFIG['verification'].get('require_captcha', True):
        if not captcha_token or not SecurityManager.verify_captcha(captcha_token):
            pending['attempts'] = pending.get('attempts', 0) + 1
            data_manager.save()
            return jsonify({"success": False, "error": "CAPTCHA verification failed"})
    
    ip_rep = SecurityManager.check_ip_reputation(client_ip)
    if not ip_rep['clean'] and CONFIG['security']['block_vpns']:
        data_manager.add_log("VPN_DETECTED", int(user_id), f"IP: {client_ip}", "warning")
        if ip_rep.get('threat_score', 0) > 75:
            return jsonify({"success": False, "error": "Suspicious network detected"})
    
    alt_check = SecurityManager.check_alt_account(int(user_id), fingerprint, client_ip)
    if alt_check['is_alt']:
        data_manager.data['stats']['alt_accounts_detected'] += 1
        data_manager.add_log("ALT_DETECTED", int(user_id), alt_check['reason'], "warning")
        if CONFIG['security']['block_alts']:
            return jsonify({"success": False, "error": "Alt account detected"})
    
    pending.update({
        'verified': True,
        'ip': client_ip,
        'fingerprint': fingerprint,
        'verified_at': datetime.now().isoformat(),
        'user_agent': data.get('user_agent', ''),
        'screen_resolution': data.get('screen_resolution', ''),
        'timezone': data.get('timezone', ''),
        'ip_reputation': ip_rep
    })
    
    data_manager.data['pending_verifications'][user_id] = pending
    data_manager.data['stats']['total_verifications'] += 1
    data_manager.save()
    
    data_manager.add_log("VERIFICATION_COMPLETE", int(user_id), f"Server: {pending['guild_name']}, IP: {client_ip}")
    
    return jsonify({
        "success": True,
        "message": "Verification successful! You can close this page.",
        "username": pending['username'],
        "server": pending['guild_name']
    })

# ============== DISCORD BOT ==============
intents = discord.Intents.default()
intents.members = True
intents.message_content = True

bot = commands.Bot(
    command_prefix=CONFIG['bot']['prefix'],
    intents=intents,
    help_command=None
)

class PersistentVerifyButton(Button):
    def __init__(self):
        super().__init__(
            label="Verify",
            style=discord.ButtonStyle.secondary,
            custom_id="persistent_verify_button_v3",
            emoji="<:choose:1470974821830627409>"
        )
    
    async def callback(self, interaction: discord.Interaction):
        user = interaction.user
        guild = interaction.guild
        
        if str(user.id) in data_manager.data['verified_users']:
            embed = discord.Embed(
                title=" Already Verified",
                description="You are already verified in this server!",
                color=CONFIG['embeds']['colors']['error']
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
        
        if not SecurityManager.check_account_age(user):
            min_days = CONFIG['security']['min_account_age_days']
            embed = discord.Embed(
                title=" Account Too New",
                description=f"Your account must be at least **{min_days}** days old to verify.\nAccount age: {(datetime.now(user.created_at.tzinfo or datetime.timezone.utc) - user.created_at).days} days",
                color=CONFIG['embeds']['colors']['error']
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
        
        code = SecurityManager.generate_code(user.id)
        
        data_manager.data['pending_verifications'][str(user.id)] = {
            "code": code,
            "username": str(user),
            "user_id": user.id,
            "avatar_url": str(user.display_avatar.url),
            "guild_id": guild.id,
            "guild_name": guild.name,
            "guild_icon": str(guild.icon.url) if guild.icon else None,
            "timestamp": time.time(),
            "attempts": 0,
            "verified": False
        }
        data_manager.save()
        
        token = encryption_manager.encrypt_params(code, user.id)
        
        domain = CONFIG['web_server']['domain']
        verification_link = f"{domain}/verify?t={token}"
        
        embed = discord.Embed(
            title="<:load:1470972555086139472> Verification Required",
            description="This server is protected by **Double Counter** with advanced security checks.",
            color=CONFIG['embeds']['colors']['info'],
            timestamp=datetime.now()
        )
        
        embed.add_field(name="> <:share2:1470974119192428648> Server", value=f"**{guild.name}**", inline=False)
        embed.add_field(name="> <:share2:1470974119192428648> Verification Link", value=f"[**Click here to verify**]({verification_link})", inline=False)
        embed.add_field(name="> <:share2:1470974119192428648> Expires", value=f"in {CONFIG['security']['code_expiry_minutes']} minutes", inline=False)
        embed.add_field(name="> <:share2:1470974119192428648>  Security", value="• VPN/Proxy Detection\n• Browser Fingerprinting\n• Alt Account Prevention\n• CAPTCHA Protection", inline=False)
        
        if guild.icon:
            embed.set_thumbnail(url=guild.icon.url)
        embed.set_footer(text=CONFIG['embeds']['footer_text'])
        
        view = View(timeout=300)
        view.add_item(discord.ui.Button(label="Verify Now", url=verification_link, style=discord.ButtonStyle.link))
        
        await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

class PersistentVerifyView(View):
    def __init__(self):
        super().__init__(timeout=None)
        self.add_item(PersistentVerifyButton())

class VerificationCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.cleanup_task.start()
        self.backup_task.start()
        self.verification_checker.start()
        self.stats_task.start()
    
    def cog_unload(self):
        self.cleanup_task.cancel()
        self.backup_task.cancel()
        self.verification_checker.cancel()
        self.stats_task.cancel()
    
    @commands.command(name="setupverify")
    @commands.has_permissions(administrator=True)
    async def setup_verify(self, ctx, channel: Optional[discord.TextChannel] = None):
        target = channel or ctx.channel
        
        embed = discord.Embed(
            description="Welcome! Please verify yourself to access the server.\n\n**Security Features:**\n<:number1:1470974824552857611> Anti-VPN/Proxy Protection\n<:number2:1470975168091525256>  Alt Account Detection\n<:number3:1470975165579001997>  Bot Prevention\n<:numberfour:1470975172428300361> Fast & Secure",
            color=CONFIG['embeds']['colors']['success'],
            timestamp=datetime.now()
        )
        
        if ctx.guild.icon:
            embed.set_thumbnail(url=ctx.guild.icon.url)
        embed.set_footer(
            text=f"{ctx.guild.name} • {CONFIG['embeds']['footer_text']}",
            icon_url=ctx.guild.icon.url if ctx.guild.icon else None
        )
        
        await target.send(embed=embed, view=PersistentVerifyView())
        await ctx.send(f" Persistent verification panel sent to {target.mention}", delete_after=5)
    
    @commands.command(name="verifyforce")
    @commands.has_permissions(administrator=True)
    async def force_verify(self, ctx, member: discord.Member):
        role_name = CONFIG['bot']['verified_role_name']
        role = discord.utils.get(ctx.guild.roles, name=role_name)
        
        if not role:
            return await ctx.send(f" Role '{role_name}' not found!")
        
        await member.add_roles(role, reason="Force verified by admin")
        
        data_manager.data['verified_users'][str(member.id)] = {
            "verified_at": time.time(),
            "by": ctx.author.id,
            "guild_id": ctx.guild.id,
            "username": str(member),
            "method": "force"
        }
        data_manager.save()
        
        embed = discord.Embed(
            title=" Force Verified",
            description=f"{member.mention} has been force verified by {ctx.author.mention}",
            color=CONFIG['embeds']['colors']['success']
        )
        await ctx.send(embed=embed)
    
    @commands.command(name="unverify")
    @commands.has_permissions(administrator=True)
    async def unverify(self, ctx, member: discord.Member):
        role_name = CONFIG['bot']['verified_role_name']
        role = discord.utils.get(ctx.guild.roles, name=role_name)
        
        if role and role in member.roles:
            await member.remove_roles(role)
        
        user_data = data_manager.data['verified_users'].get(str(member.id), {})
        if user_data.get('fingerprint'):
            data_manager.data['blocked_fingerprints'].append(user_data['fingerprint'])
        
        if str(member.id) in data_manager.data['verified_users']:
            del data_manager.data['verified_users'][str(member.id)]
            data_manager.save()
        
        await ctx.send(f" {member.mention} has been unverified and blocked.")
    
    @commands.command(name="vstats")
    @commands.has_permissions(administrator=True)
    async def stats(self, ctx):
        stats = data_manager.data.get('stats', {})
        pending = len(data_manager.data['pending_verifications'])
        verified = len(data_manager.data['verified_users'])
        blocked = len(data_manager.data['blocked_fingerprints'])
        
        embed = discord.Embed(
            title=" Verification Statistics",
            color=CONFIG['embeds']['colors']['info'],
            timestamp=datetime.now()
        )
        
        embed.add_field(name=" Total Verifications", value=stats.get('total_verifications', 0), inline=True)
        embed.add_field(name=" Pending", value=pending, inline=True)
        embed.add_field(name=" Verified Users", value=verified, inline=True)
        embed.add_field(name=" Blocked Fingerprints", value=blocked, inline=True)
        embed.add_field(name=" Alt Accounts Caught", value=stats.get('alt_accounts_detected', 0), inline=True)
        embed.add_field(name=" Blocked Attempts", value=stats.get('blocked_attempts', 0), inline=True)
        
        await ctx.send(embed=embed)
    
    @tasks.loop(minutes=1)
    async def verification_checker(self):
        data = data_manager.data
        to_remove = []
        
        for user_id, info in list(data['pending_verifications'].items()):
            if info.get('verified') and not info.get('role_assigned'):
                guild_id = info.get('guild_id')
                guild = self.bot.get_guild(guild_id)
                
                if guild:
                    member = guild.get_member(int(user_id))
                    if member:
                        role_name = CONFIG['bot']['verified_role_name']
                        role = discord.utils.get(guild.roles, name=role_name)
                        
                        if role:
                            try:
                                await member.add_roles(role, reason="Double Counter Verification")
                                info['role_assigned'] = True
                                info['role_assigned_at'] = time.time()
                                
                                data['verified_users'][user_id] = {
                                    "verified_at": time.time(),
                                    "username": info['username'],
                                    "guild_id": guild_id,
                                    "ip": info.get('ip'),
                                    "fingerprint": info.get('fingerprint'),
                                    "method": "standard"
                                }
                                to_remove.append(user_id)
                                
                                data_manager.add_log("ROLE_ASSIGNED", int(user_id), f"Guild: {guild.name}")
                                
                                if CONFIG['verification'].get('send_dm_confirmation', True):
                                    try:
                                        embed = discord.Embed(
                                            title="<:load:1470972555086139472> Verification Complete",
                                            description=f"You have been successfully verified in **{guild.name}**!",
                                            color=CONFIG['embeds']['colors']['success']
                                        )
                                        await member.send(embed=embed)
                                    except:
                                        pass
                            except Exception as e:
                                logger.error(f"Error assigning role: {e}")
        
        for uid in to_remove:
            if uid in data['pending_verifications']:
                del data['pending_verifications'][uid]
        
        if to_remove:
            data_manager.save()
    
    @tasks.loop(minutes=5)
    async def cleanup_task(self):
        current = time.time()
        expired = []
        expiry = CONFIG['security']['code_expiry_minutes'] * 60
        
        for uid, info in data_manager.data['pending_verifications'].items():
            if current - info['timestamp'] > expiry and not info.get('verified'):
                expired.append(uid)
        
        for uid in expired:
            del data_manager.data['pending_verifications'][uid]
        
        if expired:
            data_manager.save()
            logger.info(f"Cleaned up {len(expired)} expired codes")
    
    @tasks.loop(hours=24)
    async def backup_task(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(data_manager.backup_dir, f"backup_{timestamp}.json")
        
        with open(backup_file, 'w', encoding='utf-8') as f:
            json.dump(data_manager.data, f, indent=4)
        
        backups = sorted([f for f in os.listdir(data_manager.backup_dir) if f.startswith('backup_')])
        for old in backups[:-10]:
            os.remove(os.path.join(data_manager.backup_dir, old))
        
        logger.info(f"Database backup created: {backup_file}")
    
    @tasks.loop(hours=1)
    async def stats_task(self):
        cutoff = time.time() - (30 * 86400)
        data_manager.data['logs'] = [
            log for log in data_manager.data.get('logs', [])
            if log['timestamp'] > cutoff
        ]
        data_manager.save()
    
    @cleanup_task.before_loop
    @backup_task.before_loop
    @verification_checker.before_loop
    @stats_task.before_loop
    async def before_tasks(self):
        await self.bot.wait_until_ready()

@bot.event
async def on_ready():
    logger.info(f'Bot logged in as {bot.user}')
    
    bot.add_view(PersistentVerifyView())
    
    await bot.change_presence(
        activity=discord.Activity(
            type=discord.ActivityType.watching,
            name=CONFIG['bot']['status']
        )
    )
    
    await bot.add_cog(VerificationCog(bot))

def run_flask():
    host = CONFIG['web_server']['host']
    port = CONFIG['web_server']['port']
    debug = CONFIG['web_server']['debug']
    
    logger.info(f"Starting Flask server on {host}:{port}")
    app.run(host=host, port=port, debug=debug, use_reloader=False, threaded=True)

if __name__ == "__main__":
    os.makedirs('web/static', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    
    try:
        bot.run(CONFIG['bot']['token'])
    except Exception as e:
        logger.critical(f"Bot crashed: {e}")
        raise
