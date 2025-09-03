from flask import Blueprint, request, redirect, url_for, flash, current_app
import razorpay
import hmac
import hashlib
import json
from datetime import datetime, timedelta
from your_models import User, Subscription, db

payment_bp = Blueprint('payment', __name__)

# Initialize Razorpay client
client = razorpay.Client(auth=(current_app.config['RAZORPAY_KEY_ID'], 
                              current_app.config['RAZORPAY_KEY_SECRET']))

@payment_bp.route('/create_order', methods=['POST'])
def create_order():
    try:
        data = request.get_json()
        plan = data.get('plan')
        amount = 29900 if plan == 'premium' else 99900  # ₹299 or ₹999 in paise
        
        order_data = {
            'amount': amount,
            'currency': 'INR',
            'receipt': f'receipt_{datetime.now().timestamp()}',
            'notes': {
                'plan': plan,
                'user_email': data.get('email')
            }
        }
        
        order = client.order.create(order_data)
        return {'order_id': order['id']}, 200
        
    except Exception as e:
        print(f"Order creation error: {str(e)}")
        return {'error': 'Order creation failed'}, 500

@payment_bp.route('/payment-success', methods=['POST'])
def payment_success():
    try:
        # Get form data
        razorpay_payment_id = request.form.get('razorpay_payment_id')
        razorpay_order_id = request.form.get('razorpay_order_id')
        razorpay_signature = request.form.get('razorpay_signature')
        plan = request.form.get('plan')
        email = request.form.get('email')

        print(f"Payment success for: {email}, Plan: {plan}")

        # Verify payment signature
        params_dict = {
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': razorpay_payment_id,
            'razorpay_signature': razorpay_signature
        }

        # Verify signature
        client.utility.verify_payment_signature(params_dict)
        
        # Immediately activate subscription
        success = activate_premium_plan(email, plan, razorpay_order_id, razorpay_payment_id)
        
        if success:
            flash('Payment successful! Premium features activated.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Payment verification failed. Please contact support.', 'error')
            return redirect(url_for('pricing'))
            
    except Exception as e:
        print(f"Payment success error: {str(e)}")
        flash('Payment processing error. Please contact support.', 'error')
        return redirect(url_for('pricing'))

@payment_bp.route('/razorpay_webhook', methods=['POST'])
def razorpay_webhook():
    try:
        # Verify webhook signature
        webhook_secret = current_app.config['RAZORPAY_WEBHOOK_SECRET']
        received_signature = request.headers.get('X-Razorpay-Signature')
        
        # Create HMAC SHA256 signature
        body = request.get_data()
        expected_signature = hmac.new(
            webhook_secret.encode('utf-8'),
            body,
            hashlib.sha256
        ).hexdigest()

        # Verify signature
        if not hmac.compare_digest(received_signature, expected_signature):
            print("Invalid webhook signature")
            return {'error': 'Invalid signature'}, 400

        # Process webhook event
        event = request.get_json()
        event_type = event.get('event')
        
        print(f"Webhook received: {event_type}")

        if event_type == 'payment.captured':
            payment_data = event['payload']['payment']['entity']
            order_id = payment_data['order_id']
            payment_id = payment_data['id']
            
            # Get order details to find user email and plan
            order_details = client.order.fetch(order_id)
            notes = order_details.get('notes', {})
            email = notes.get('user_email')
            plan = notes.get('plan')
            
            if email and plan:
                # Update subscription as backup
                activate_premium_plan(email, plan, order_id, payment_id)
                print(f"Webhook: Activated plan for {email}")

        return {'status': 'success'}, 200

    except Exception as e:
        print(f"Webhook error: {str(e)}")
        return {'error': str(e)}, 500

def activate_premium_plan(email, plan, order_id, payment_id):
    try:
        user = User.query.filter_by(email=email).first()
        
        if not user:
            print(f"User not found: {email}")
            return False

        # Calculate subscription duration
        start_date = datetime.utcnow()
        if plan == 'premium':
            end_date = start_date + timedelta(days=60)  # 2 months
        else:  # enterprise or other plans
            end_date = start_date + timedelta(days=365)  # 1 year

        # Check existing subscription
        subscription = Subscription.query.filter_by(user_id=user.id).first()
        
        if subscription:
            # Update existing subscription
            subscription.plan = plan
            subscription.status = 'active'
            subscription.start_date = start_date
            subscription.end_date = end_date
            subscription.razorpay_order_id = order_id
            subscription.razorpay_payment_id = payment_id
        else:
            # Create new subscription
            subscription = Subscription(
                user_id=user.id,
                plan=plan,
                status='active',
                start_date=start_date,
                end_date=end_date,
                razorpay_order_id=order_id,
                razorpay_payment_id=payment_id
            )
            db.session.add(subscription)

        db.session.commit()
        print(f"Premium plan activated for {email}, Plan: {plan}")
        return True
        
    except Exception as e:
        db.session.rollback()
        print(f"Subscription activation error: {str(e)}")
        return False
